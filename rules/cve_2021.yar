// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2021_1497_hyperflex_hx_data_platform {
    meta:
        attack_type = "cve_2021_1497"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Cisco HyperFlex HX Data Platform - Remote Command Execution: Cisco HyperFlex HX contains multiple vulnerabilities in the web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-1497"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-1497, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-1497.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/auth\/change(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_20091_wsr_2533dhpl2_bk {
    meta:
        attack_type = "cve_2021_20091"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Buffalo WSR-2533DHPL2 - Configuration File Injection: The web interfaces of Buffalo WSR-2533DHPL2 firmware version <= 1.02 and WSR-2533DHP3 firmware version <= 1.24 does not properly sanitize user input. An authenticated remote attacker could leverage this vulnerability to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20091"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20091, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20091.yaml"
    strings:
        $path0 = /\/images\/\.\.\/apply_abstract\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])submit_button=ping\.html(&|$)/ nocase
        $param1 = /(^|[?&;])action_params=blink_time=5(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_20114_tcexam {
    meta:
        attack_type = "cve_2021_20114"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TCExam <= 14.8.1 - Sensitive Information Exposure: When installed following the default/recommended settings, TCExam <= 14.8.1 allowed unauthenticated users to access the /cache/backup/ directory, which includes sensitive database backup files."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20114"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20114, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20114.yaml"
    strings:
        $path0 = "/cache/backup/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_20123_vigorconnect {
    meta:
        attack_type = "cve_2021_20123"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Draytek VigorConnect 1.6.0-B - Local File Inclusion: Draytek VigorConnect 1.6.0-B3 is susceptible to local file inclusion in the file download functionality of the DownloadFileServlet endpoint. An unauthenticated attacker could leverage this vulnerability to download arbitrary."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20123"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20123, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20123.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ACSServer\/DownloadFileServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])show_file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])type=uploadfile(&|$)/ nocase
        $param2 = /(^|[?&;])path=anything(&|$)/ nocase
        $param3 = /(^|[?&;])show_file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/windows\/win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_20124_vigorconnect {
    meta:
        attack_type = "cve_2021_20124"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Draytek VigorConnect 6.0-B3 - Local File Inclusion: Draytek VigorConnect 1.6.0-B3 is susceptible to local file inclusion in the file download functionality of the WebServlet endpoint. An unauthenticated attacker could leverage this vulnerability to download arbitrary files from."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20124"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20124, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20124.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ACSServer\/WebServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])act=getMapImg_acs2(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_20137_gryphon_tower {
    meta:
        attack_type = "cve_2021_20137"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gryphon Tower - Cross-Site Scripting: Gryphon Tower router web interface contains a reflected cross-site scripting vulnerability in the url parameter of the /cgi-bin/luci/site_access/ page. An attacker can exploit this issue by tricking a user into following a specially crafted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20137.yaml"
        response_type = "xss"
    strings:
        $path0 = "/cgi-bin/luci/site_access/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_20150_tew_827dru_firmware {
    meta:
        attack_type = "cve_2021_20150"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Trendnet AC2600 TEW-827DRU - Credentials Disclosure: Trendnet AC2600 TEW-827DRU version 2.08B01 improperly discloses information via redirection from the setup wizard. A user may view information as Admin by manually browsing to the setup wizard and forcing it to redirect to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20150.yaml"
    strings:
        $param0 = /(^|[?&;])html_response_page=ftpserver\.asp(&|$)/ nocase
        $param1 = /(^|[?&;])html_response_return_page=ftpserver\.asp(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_20167_rax43_firmware {
    meta:
        attack_type = "cve_2021_20167"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netgear RAX43 1.0.3.96 - Command Injection/Authentication Bypass Buffer Overrun: Netgear RAX43 version 1.0.3.96 contains a command injection and authentication bypass vulnerability. The readycloud_control.cgi CGI application is vulnerable to command injection in the name."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20167"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20167, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20167.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/readycloud_control\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_20323_keycloak {
    meta:
        attack_type = "cve_2021_20323"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Keycloak 10.0.0 - 18.0.0 - Cross-Site Scripting: Keycloak 10.0.0 to 18.0.0 contains a cross-site scripting vulnerability via the client-registrations endpoint. On a POST request, the application does not sanitize an unknown attribute name before including it in the error."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-20323"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20323, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-20323.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/auth\/realms\/master\/clients-registrations\/default(\/|;|$)/ nocase
        $path1 = /\/auth\/realms\/master\/clients-registrations\/openid-connect(\/|;|$)/ nocase
        $path2 = /\/realms\/master\/clients-registrations\/default(\/|;|$)/ nocase
        $path3 = /\/realms\/master\/clients-registrations\/openid-connect(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21234_spring_boot_actuator_logview {
    meta:
        attack_type = "cve_2021_21234"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Spring Boot Actuator Logview Directory Traversal: spring-boot-actuator-logview before version 0.2.13 contains a directory traversal vulnerability in libraries that adds a simple logfile viewer as a spring boot actuator endpoint (maven package."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21234"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21234, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21234.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/manage\/log\/view(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21287_minio {
    meta:
        attack_type = "cve_2021_21287"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MinIO Browser API - Server-Side Request Forgery: MinIO Browser API before version RELEASE.2021-01-30T00-20-58Z contains a server-side request forgery vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21287.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/minio\/webrpc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21307_lucee_server {
    meta:
        attack_type = "cve_2021_21307"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Lucee Admin - Remote Code Execution: Lucee Admin before versions 5.3.7.47, 5.3.6.68 or 5.3.5.96 contains an unauthenticated remote code execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21307"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21307, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21307.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/lucee\/admin\/imgProcess\.cfm(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file=\/whatever(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_21311_adminer {
    meta:
        attack_type = "cve_2021_21311"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Adminer <4.7.9 - Server-Side Request Forgery: Adminer before 4.7.9 is susceptible to server-side request forgery due to exposure of sensitive information in error messages. Users of Adminer versions bundling all drivers, e.g. adminer.php, are affected. An attacker can possibly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21311"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21311, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21311.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])auth\[driver\]=elastic(&|$)/ nocase
        $param1 = /(^|[?&;])auth\[server\]=example\.org(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_21315_systeminformation {
    meta:
        attack_type = "cve_2021_21315"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Node.JS System Information Library <5.3.1 - Remote Command Injection: Node.JS System Information Library System before version 5.3.1 is susceptible to remote command injection. Node.JS (npm package 'systeminformation') is an open source collection of functions to retrieve."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21315.yaml"
    strings:
        $path0 = /\/api\/getServices(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21389_buddypress {
    meta:
        attack_type = "cve_2021_21389"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BuddyPress REST API <7.2.1 - Privilege Escalation/Remote Code Execution: WordPress BuddyPress before version 7.2.1 is susceptible to a privilege escalation vulnerability that can be leveraged to perform remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21389.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-json\/buddypress\/v1\/signup(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21745_mf971r_firmware {
    meta:
        attack_type = "cve_2021_21745"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ZTE MF971R - Referer authentication bypass: ZTE MF971R product has a Referer authentication bypass vulnerability. Without CSRF verification, an attackercould use this vulnerability to perform illegal authorization operations by sending a request to the user to click."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21745"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21745, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21745.yaml"
    strings:
        $path0 = /\/goform\/goform_get_cmd_process(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21799_r_seenet {
    meta:
        attack_type = "cve_2021_21799"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Advantech R-SeeNet 2.4.12 - Cross-Site Scripting: Advantech R-SeeNet 2.4.12 contains a reflected cross-site scripting vulnerability in the telnet_form.php script functionality."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21799"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21799, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21799.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/php\/telnet_form\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21881_premierwave_2050_firmware {
    meta:
        attack_type = "cve_2021_21881"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Lantronix PremierWave 2050 8.9.0.0R4 - Remote Command Injection: Lantronix PremierWave 2050 8.9.0.0R4 contains an OS command injection vulnerability. A specially-crafted HTTP request can lead to command in the Web Manager Wireless Network Scanner. An attacker can make an."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21881"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21881, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21881.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])ajax=WLANScanSSID(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_21973_cloud_foundation {
    meta:
        attack_type = "cve_2021_21973"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "VMware vSphere - Server-Side Request Forgery: VMware vSphere (HTML5) is susceptible to server-side request forgery due to improper validation of URLs in a vCenter Server plugin. An attacker with network access to port 443 can exploit this issue by sending a POST request to the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21973"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21973, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21973.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/ui\/vropspluginui\/rest\/services\/getvcdetails(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_21975_cloud_foundation {
    meta:
        attack_type = "cve_2021_21975"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "vRealize Operations Manager API - Server-Side Request Forgery: vRealize Operations Manager API is susceptible to server-side request forgery. A malicious actor with network access to the vRealize Operations Manager API can steal administrative credentials or trigger remote code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-21975"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21975, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-21975.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/casa\/nodes\/thumbprints(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_22017_vcenter_server {
    meta:
        attack_type = "cve_2021_22017"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "vCenter Server - Improper Access Control: Rhttproxy as used in vCenter Server contains a vulnerability due to improper implementation of URI normalization. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to bypass proxy leading to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22017"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22017, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22017.yaml"
    strings:
        $path0 = /\/analytics\/ceip\/sdk\/\.\.;\/\.\.;\/\.\.;\/analytics\/ph\/api\/dataapp\/agent(\/|;|$)/ nocase
        $param0 = /(^|[?&;])_c=vSphere\.vapi\.6_7(&|$)/ nocase
        $param1 = /(^|[?&;])_i=9D36C850-1612-4EC4-B8DD-50BA239A25BB(&|$)/ nocase
        $param2 = /(^|[?&;])action=collect(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_22054_workspace_one_uem_console {
    meta:
        attack_type = "cve_2021_22054"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "VMWare Workspace ONE UEM - Server-Side Request Forgery: VMware Workspace ONE UEM console 20.0.8 prior to 20.0.8.37, 20.11.0 prior to 20.11.0.40, 21.2.0 prior to 21.2.0.27, and 21.5.0 prior to 21.5.0.37 contain a server-side request forgery vulnerability. This issue may allow a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22054"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22054, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22054.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/Catalog\/BlobHandler\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_22122_fortiweb {
    meta:
        attack_type = "cve_2021_22122"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FortiWeb - Cross Site Scripting: FortiWeb 6.3.0 through 6.3.7 and versions before 6.2.4 contain an unauthenticated cross-site scripting vulnerability. Improper neutralization of input during web page generation can allow a remote attacker to inject malicious payload in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22122"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22122, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22122.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/omni_success(\/|;|$)/ nocase
        $param0 = /(^|[?&;])data=';alert\('document\.domain'\);\/\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_22502_operation_bridge_reporter {
    meta:
        attack_type = "cve_2021_22502"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Micro Focus Operations Bridge Reporter - Remote Code Execution: Micro Focus Operations Bridge Reporter 10.40 is susceptible to remote code execution. An attacker can potentially execute malware, obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22502"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22502, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22502.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/AdminService\/urest\/v1\/LogonResource(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_22707_evlink_city_evc1s22p4_firmware {
    meta:
        attack_type = "cve_2021_22707"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "EVlink City < R8 V3.4.0.1 - Authentication Bypass: A CWE-798: Use of Hard-coded Credentials vulnerability exists in EVlink City (EVC1S22P4 / EVC1S7P4 all versions prior to R8 V3.4.0.1), EVlink Parking (EVW2 / EVF2 / EV.2 all versions prior to R8 V3.4.0.1), and EVlink Smart."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22707"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22707, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22707.yaml"
    strings:
        $path0 = /\/cgi-bin\/cgiServer(\/|;|$)/ nocase
        $param0 = /(^|[?&;])worker=IndexNew(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_22873_revive_adserver {
    meta:
        attack_type = "cve_2021_22873"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Revive Adserver <5.1.0 - Open Redirect: Revive Adserver before 5.1.0 contains an open redirect vulnerability via the dest, oadest, and ct0 parameters of the lg.php and ck.php delivery scripts. An attacker can redirect a user to a malicious site and possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22873"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22873, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22873.yaml"
    strings:
        $path0 = /\/ads\/www\/delivery\/lg\.php(\/|;|$)/ nocase
        $path1 = /\/adserve\/www\/delivery\/lg\.php(\/|;|$)/ nocase
        $path2 = /\/adserver\/www\/delivery\/lg\.php(\/|;|$)/ nocase
        $path3 = /\/openx\/www\/delivery\/lg\.php(\/|;|$)/ nocase
        $path4 = /\/revive\/www\/delivery\/lg\.php(\/|;|$)/ nocase
        $path5 = /\/www\/delivery\/lg\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_22911_rocket_chat {
    meta:
        attack_type = "cve_2021_22911"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Rocket.Chat <=3.13 - NoSQL Injection: Rocket.Chat 3.11, 3.12 and 3.13 contains a NoSQL injection vulnerability which allows unauthenticated access to an API endpoint. An attacker can possibly obtain sensitive information from a database, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22911"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22911, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22911.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/v1\/method\.callAnon\/getPasswordPolicy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_22986_big_ip_access_policy_manager {
    meta:
        attack_type = "cve_2021_22986"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "F5 iControl REST - Remote Command Execution: F5 iControl REST interface is susceptible to remote command execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-22986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-22986.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mgmt\/shared\/authn\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_23241_mercury_x18g_firmware {
    meta:
        attack_type = "cve_2021_23241"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MERCUSYS Mercury X18G 1.0.5 Router - Local File Inclusion: MERCUSYS Mercury X18G 1.0.5 devices are vulnerable to local file inclusion via ../ in conjunction with a loginLess or login.htm URI (for authentication bypass) to the web server, as demonstrated by the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-23241"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-23241, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-23241.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/loginLess\/\.\.\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24146_modern_events_calendar_lite {
    meta:
        attack_type = "cve_2021_24146"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Modern Events Calendar Lite <5.16.5 - Sensitive Information Disclosure: WordPress Modern Events Calendar Lite before 5.16.5 does not properly restrict access to the export files, allowing unauthenticated users to exports all events data in CSV or XML format."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24146"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24146, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24146.yaml"
    strings:
        $param0 = /(^|[?&;])mec-ix-action=export-events(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24155_backup_guard {
    meta:
        attack_type = "cve_2021_24155"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress BackupGuard <1.6.0 - Authenticated Arbitrary File Upload: WordPress Backup Guard plugin before 1.6.0 is susceptible to authenticated arbitrary file upload. The plugin does not ensure that imported files are in SGBP format and extension, allowing high-privilege users."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24155"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24155, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24155.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/backup-guard/" ascii nocase
        $param0 = /(^|[?&;])action=backup_guard_importBackup(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24165_ninja_forms {
    meta:
        attack_type = "cve_2021_24165"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Ninja Forms <3.4.34 - Open Redirect: WordPress Ninja Forms plugin before 3.4.34 contains an open redirect vulnerability via the wp_ajax_nf_oauth_connect AJAX action, due to the use of a user-supplied redirect parameter and no protection in place. An attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24165"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24165, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24165.yaml"
    strings:
        $param0 = /(^|[?&;])action=nf_oauth_connect(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24170_user_profile_picture {
    meta:
        attack_type = "cve_2021_24170"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "User Profile Picture < 2.5.0 - Sensitive Information Disclosure: The REST API endpoint get_users in the User Profile Picture WordPress plugin before 2.5.0 returned more information than was required for its functionality to users with the upload_files capability. This included."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24170"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24170, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24170.yaml"
    strings:
        $param0 = /(^|[?&;])rest_route=\/mpp\/v2\/get_users(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24210_phastpress {
    meta:
        attack_type = "cve_2021_24210"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress PhastPress <1.111 - Open Redirect: WordPress PhastPress plugin before 1.111 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24210"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24210, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24210.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/phastpress\/phast\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])service=scripts(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24212_help_scout {
    meta:
        attack_type = "cve_2021_24212"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WooCommerce Help Scout - Arbitrary File Upload: WooCommerce Help Scout plugin before version 2.9.1 contains an unrestricted file upload vulnerability. The vulnerability allows unauthenticated users to upload arbitrary files to the server which by default will end up in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24212"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24212, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24212.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/hstmp/" ascii nocase
        $param0 = /(^|[?&;])action=wc_help_scout_upload_attachments(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24213_givewp {
    meta:
        attack_type = "cve_2021_24213"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GiveWP <= 2.9.7 - Cross-Site Scripting: GiveWP Donation Plugin and Fundraising Platform plugin for WordPress versions before 2.10.0 is vulnerable to Reflected Cross-Site Scripting via the 's' parameter in the admin Donors page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24213"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24213, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24213.yaml"
    strings:
        $param0 = /(^|[?&;])post_type=give_forms(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24219_focusblog {
    meta:
        attack_type = "cve_2021_24219"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "All Thrive Themes and Plugins - Unauthenticated Option Update: The Thrive Optimize WordPress plugin before 1.4.13.3, Thrive Comments WordPress plugin before 1.4.15.3, Thrive Headline Optimizer WordPress plugin before 1.3.7.3, Thrive Leads WordPress plugin before 2.3.9.4, Thrive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24219.yaml"
    strings:
        $path0 = /\/wp-json\/td\/v1\/optin\/subscription(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24227_patreon_wordpress {
    meta:
        attack_type = "cve_2021_24227"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Patreon WordPress <1.7.0 - Unauthenticated Local File Inclusion: Patreon WordPress before version 1.7.0 is vulnerable to unauthenticated local file inclusion that could be abused by anyone visiting the site. Exploitation by an attacker could leak important internal files like."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24227"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24227, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24227.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])patron_only_image=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])patreon_action=serve_patron_only_image(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24236_imagements {
    meta:
        attack_type = "cve_2021_24236"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Imagements <=1.2.5 - Arbitrary File Upload: WordPress Imagements plugin through 1.2.5 is susceptible to arbitrary file upload which can lead to remote code execution. The plugin allows images to be uploaded in comments but only checks for the Content-Type in the."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24236.yaml"
    strings:
        $path0 = "/wp-content/plugins/imagements/images/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24239_pie_register {
    meta:
        attack_type = "cve_2021_24239"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Pie Register <3.7.0.1 - Cross-Site Scripting: WordPress Pie Register plugin before 3.7.0.1 is susceptible to cross-site scripting. The plugin does not sanitize the invitaion_code GET parameter when outputting it in the Activation Code page. An attacker can inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24239"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24239, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24239.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=pr_new_registration_form(&|$)/ nocase
        $param1 = /(^|[?&;])invitaion_code=PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pOzwvc2NyaXB0Pg==(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24274_ultimate_maps {
    meta:
        attack_type = "cve_2021_24274"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Supsystic Ultimate Maps <1.2.5 - Cross-Site Scripting: WordPress Supsystic Ultimate Maps plugin before 1.2.5 contains an unauthenticated reflected cross-site scripting vulnerability due to improper sanitization of the tab parameter on the options page before."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24274"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24274, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24274.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=ultimate-maps-supsystic(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24275_popup {
    meta:
        attack_type = "cve_2021_24275"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Popup by Supsystic <1.10.5 - Cross-Site scripting: WordPress Popup by Supsystic before 1.10.5 did not sanitize the tab parameter of its options page before outputting it in an attribute, leading to a reflected cross-site scripting issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24275"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24275, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24275.yaml"
    strings:
        $param0 = /(^|[?&;])page=popup-wp-supsystic(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24276_contact_form {
    meta:
        attack_type = "cve_2021_24276"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Supsystic Contact Form <1.7.15 - Cross-Site Scripting: WordPress Supsystic Contact Form plugin before 1.7.15 contains a cross-site scripting vulnerability. It does not sanitize the tab parameter of its options page before outputting it in an attribute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24276"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24276, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24276.yaml"
    strings:
        $param0 = /(^|[?&;])page=contact-form-supsystic(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24278_redirection_for_contact_form_7 {
    meta:
        attack_type = "cve_2021_24278"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Contact Form 7 <2.3.4 - Arbitrary Nonce Generation: WordPress Contact Form 7 before version 2.3.4 allows unauthenticated users to use the wpcf7r_get_nonce AJAX action to retrieve a valid nonce for any WordPress action/function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24278"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24278, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24278.yaml"
    strings:
        $param0 = /(^|[?&;])param=wp_rest(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24285_cars_seller_auto_classifieds_s {
    meta:
        attack_type = "cve_2021_24285"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Car Seller - Auto Classifieds Script - SQL Injection: The request_list_request AJAX call of the Car Seller - Auto Classifieds Script WordPress plugin through 2.1.0, available to both authenticated and unauthenticated users, does not sanitize, validate or escape the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24285"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24285, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24285.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=request_list_request(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24286_redirect_404_to_parent {
    meta:
        attack_type = "cve_2021_24286"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Redirect 404 to Parent 1.3.0 - Cross-Site Scripting: The settings page of the plugin did not properly sanitise the tab parameter before outputting it back, leading to a reflected Cross-Site Scripting issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24286"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24286, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24286.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=moove-redirect-settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24287_select_all_categories_and_taxo {
    meta:
        attack_type = "cve_2021_24287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Select All Categories and Taxonomies <1.3.2 - Cross-Site Scripting: WordPress Select All Categories and Taxonomies plugin before 1.3.2 contains a cross-site scripting vulnerability. The settings page of the plugin does not properly sanitize the tab parameter before."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24287.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=moove-taxonomy-settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24288_acymailing {
    meta:
        attack_type = "cve_2021_24288"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress AcyMailing <7.5.0 - Open Redirect: WordPress AcyMailing plugin before 7.5.0 contains an open redirect vulnerability due to improper sanitization of the redirect parameter. An attacker turning the request from POST to GET can craft a link containing a potentially."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24288"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24288, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24288.yaml"
    strings:
        $param0 = /(^|[?&;])page=acymailing_front(&|$)/ nocase
        $param1 = /(^|[?&;])ctrl=frontusers(&|$)/ nocase
        $param2 = /(^|[?&;])user\[email\]=example@mail\.com(&|$)/ nocase
        $param3 = /(^|[?&;])task=subscribe(&|$)/ nocase
        $param4 = /(^|[?&;])option=acymailing(&|$)/ nocase
        $param5 = /(^|[?&;])acy_source=widget 2(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24298_simple_giveaways {
    meta:
        attack_type = "cve_2021_24298"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Simple Giveaways <2.36.2 - Cross-Site Scripting: WordPress Simple Giveaways plugin before 2.36.2 contains a cross-site scripting vulnerability via the method and share GET parameters of the Giveaway pages, which are not sanitized, validated, or escaped before being."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24298"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24298, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24298.yaml"
        response_type = "xss"
    strings:
        $path0 = "/giveaway/mygiveaways/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24300_product_slider_for_woocommerce {
    meta:
        attack_type = "cve_2021_24300"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WooCommerce <1.13.22 - Cross-Site Scripting: WordPress WooCommerce before 1.13.22 contains a reflected cross-site scripting vulnerability via the slider import search feature because it does not properly sanitize the keyword GET parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24300"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24300, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24300.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=wcps(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24335_car_repair_services_auto_mecha {
    meta:
        attack_type = "cve_2021_24335"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Car Repair Services & Auto Mechanic Theme <4.0 - Cross-Site Scripting: WordPress Car Repair Services & Auto Mechanic before 4.0 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the serviceestimatekey parameter before outputting it."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24335"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24335, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24335.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/car1\/estimateresult\/result(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24342_jnews {
    meta:
        attack_type = "cve_2021_24342"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress JNews Theme <8.0.6 - Cross-Site Scripting: WordPress JNews theme before 8.0.6 contains a reflected cross-site scripting vulnerability. It does not sanitize the cat_id parameter in the POST request /?ajax-request=jnews (with action=jnews_build_mega_category_*)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24342"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24342, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24342.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])ajax-request=jnews(&|$)/ nocase
        $param1 = /(^|[?&;])action=jnews_build_mega_category_2(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24347_sp_project_document_manager {
    meta:
        attack_type = "cve_2021_24347"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress SP Project & Document Manager <4.22 - Authenticated Shell Upload: WordPress SP Project & Document Manager plugin before 4.22 is susceptible to authenticated shell upload. The plugin allows users to upload files; however, the plugin attempts to prevent PHP and other."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24347"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24347, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24347.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/sp-client-document-manager/1/" ascii nocase
        $param0 = /(^|[?&;])page=sp-client-document-manager-fileview(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24351_the_plus_addons_for_elementor {
    meta:
        attack_type = "cve_2021_24351"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress The Plus Addons for Elementor <4.1.12 - Cross-Site Scripting: WordPress The Plus Addons for Elementor plugin before 4.1.12 is susceptible to cross-site scripting. The plugin does not properly sanitize some of its fields in the heplus_more_post AJAX action, which is."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24351"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24351, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24351.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=theplus_more_post(&|$)/ nocase
        $param1 = /(^|[?&;])post_load=products(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24358_the_plus_addons_for_elementor {
    meta:
        attack_type = "cve_2021_24358"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Plus Addons for Elementor Page Builder < 4.1.10 - Open Redirect: WordPress Plus Addons for Elementor Page Builder before 4.1.10 did not validate a redirect parameter on a specifically crafted URL before redirecting the user to it, leading to an open redirect issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24358"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24358, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24358.yaml"
    strings:
        $param0 = /(^|[?&;])action=theplusrp(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24364_jannah {
    meta:
        attack_type = "cve_2021_24364"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Jannah Theme <5.4.4 - Cross-Site Scripting: WordPress Jannah theme before 5.4.4 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the options JSON parameter in its tie_get_user_weather AJAX action before outputting it back in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24364"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24364, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24364.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=tie_get_user_weather(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24370_fancy_product_designer {
    meta:
        attack_type = "cve_2021_24370"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Fancy Product Designer <4.6.9 - Arbitrary File Upload: WordPress Fancy Product Designer plugin before 4.6.9 is susceptible to an arbitrary file upload. An attacker can upload malicious files and execute code on the server, modify data, and/or gain full control over a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24370"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24370, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24370.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-content\/plugins\/fancy-product-designer\/inc\/custom-image-handler\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24389_foodbakery {
    meta:
        attack_type = "cve_2021_24389"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress FoodBakery <2.2 - Cross-Site Scripting: WordPress FoodBakery before 2.2 contains an unauthenticated reflected cross-site scripting vulnerability. It does not properly sanitize the foodbakery_radius parameter before outputting it back in the response."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24389.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])foodbakery_locations_position=filter(&|$)/ nocase
        $param1 = /(^|[?&;])search_type=autocomplete(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24409_prismatic {
    meta:
        attack_type = "cve_2021_24409"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Prismatic < 2.8 - Cross-Site Scripting: The plugin does not escape the 'tab' GET parameter before outputting it back in an attribute, leading to a reflected Cross-Site Scripting issue which will be executed in the context of a logged in administrator"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24409"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24409, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24409.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=prismatic(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24435_titan_framework {
    meta:
        attack_type = "cve_2021_24435"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Titan Framework plugin <= 1.12.1 - Cross-Site Scripting: The iframe-font-preview.php file of the titan-framework does not properly escape the font-weight and font-family GET parameters before outputting them back in an href attribute, leading to Reflected Cross-Site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24435"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24435, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24435.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/titan-framework\/lib\/iframe-font-preview\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])font-type=google(&|$)/ nocase
        $param1 = /(^|[?&;])font-family='\/onerror='alert\(document\.domain\)'\/b='(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24442_poll_survey_questionnaire_and {
    meta:
        attack_type = "cve_2021_24442"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wordpress Polls Widget < 1.5.3 - SQL Injection: The Poll, Survey, Questionnaire and Voting system WordPress plugin before 1.5.3 did not sanitise, escape or validate the date_answers[] POST parameter before using it in a SQL statement when sending a Poll result, allowing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24442.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])poll_answer_securety=8df73ed4ee(&|$)/ nocase
        $param1 = /(^|[?&;])date_answers\[0\]=SLEEP\(5\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24452_w3_total_cache {
    meta:
        attack_type = "cve_2021_24452"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress W3 Total Cache <2.1.5 - Cross-Site Scripting: WordPress W3 Total Cache plugin before 2.1.5 is susceptible to cross-site scripting via the extension parameter in the Extensions dashboard, when the setting 'Anonymously track usage to improve product quality' is enabled.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24452"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24452, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24452.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])extension='-alert\(document\.domain\)-'(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24488_post_grid {
    meta:
        attack_type = "cve_2021_24488"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Post Grid <2.1.8 - Cross-Site Scripting: WordPress Post Grid plugin before 2.1.8 contains a reflected cross-site scripting vulnerability. The slider import search feature and tab parameter of thesettings are not properly sanitized before being output back in the pages,"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24488"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24488, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24488.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=post_grid(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24495_marmoset_viewer {
    meta:
        attack_type = "cve_2021_24495"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wordpress Marmoset Viewer <1.9.3 - Cross-Site Scripting: WordPress Marmoset Viewer plugin before 1.9.3 contains a cross-site scripting vulnerability. It does not property sanitize, validate, or escape the 'id' parameter before outputting back in the page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24495"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24495, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24495.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/marmoset-viewer\/mviewer\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24498_calendar_event_multi_view {
    meta:
        attack_type = "cve_2021_24498"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Calendar Event Multi View <1.4.01 - Cross-Site Scripting: WordPress Calendar Event Multi View plugin before 1.4.01 contains an unauthenticated reflected cross-site scripting vulnerability. It does not sanitize or escape the 'start' and 'end' GET parameters before."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24498"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24498, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24498.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])cpmvc_do_action=mvparse(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24499_workreap {
    meta:
        attack_type = "cve_2021_24499"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Workreap - Remote Code Execution: WordPress Workreap theme is susceptible to remote code execution. The AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24499"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24499, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24499.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/workreap-temp/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24510_mf_gig_calendar {
    meta:
        attack_type = "cve_2021_24510"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress MF Gig Calendar <=1.1 - Cross-Site Scripting: WordPress MF Gig Calendar plugin 1.1 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize or escape the id GET parameter before outputting back in the admin dashboard when editing an event."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24510"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24510, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24510.yaml"
    strings:
        $param0 = /(^|[?&;])page=mf_gig_calendar(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24627_g_auto_hyperlink {
    meta:
        attack_type = "cve_2021_24627"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "G Auto-Hyperlink <= 1.0.1 - SQL Injection: The G Auto-Hyperlink WordPress plugin through 1.0.1 does not sanitise or escape an 'id' GET parameter before using it in a SQL statement, to select data to be displayed in the admin dashboard, leading to an authenticated SQL injection"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24627"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24627, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24627.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])page=g-auto-hyperlink-edit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24666_podlove_podcast_publisher {
    meta:
        attack_type = "cve_2021_24666"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Podlove Podcast Publisher <3.5.6 - SQL Injection: WordPress Podlove Podcast Publisher plugin before 3.5.6 is susceptible to SQL injection. The Social & Donations module, not activated by default, adds the REST route /services/contributor/(?P<id>[/d]+) and takes id and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24666"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24666, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24666.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])rest_route=\/podlove\/v1\/social\/services\/contributor\/1(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24681_duplicate_page {
    meta:
        attack_type = "cve_2021_24681"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Duplicate Page WordPress - Stored Cross-Site Scripting: Duplicate Page WordPress plugin <= 4.4.2 contains a stored cross-site scripting caused by unsanitized Duplicate Post Suffix settings in output, letting high privilege users execute malicious scripts, exploit requires high."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24681"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24681, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24681.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=duplicate_page_settings(&|$)/ nocase
        $param1 = /(^|[?&;])duplicate_post_status=draft(&|$)/ nocase
        $param2 = /(^|[?&;])duplicate_post_redirect=to_list(&|$)/ nocase
        $param3 = /(^|[?&;])submit_duplicate_page=Save Changes(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24750_wp_visitor_statistics_real_tim {
    meta:
        attack_type = "cve_2021_24750"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Visitor Statistics (Real Time Traffic) <4.8 -SQL Injection: WordPress Visitor Statistics (Real Time Traffic) plugin before 4.8 does not properly sanitize and escape the refUrl in the refDetails AJAX action, which is available to any authenticated user. This could."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24750"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24750, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24750.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=refDetails(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24838_anycomment {
    meta:
        attack_type = "cve_2021_24838"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress AnyComment <0.3.5 - Open Redirect: WordPress AnyComment plugin before 0.3.5 contains an open redirect vulnerability via an API endpoint which passes user input via the redirect parameter to the wp_redirect() function without being validated. An attacker can redirect a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24838"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24838, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24838.yaml"
    strings:
        $path0 = /\/wp-json\/anycomment\/v1\/auth\/wordpress(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_24875_ecommerce_product_catalog {
    meta:
        attack_type = "cve_2021_24875"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress eCommerce Product Catalog <3.0.39 - Cross-Site Scripting: WordPress eCommerce Product Catalog plugin before 3.0.39 contains a cross-site scripting vulnerability. The plugin does not escape the ic-settings-search parameter before outputting it back in the page in an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24875.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=al_product(&|$)/ nocase
        $param1 = /(^|[?&;])page=product-settings\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24876_registrations_for_the_events_c {
    meta:
        attack_type = "cve_2021_24876"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Registrations for The Events Calendar < 2.7.5 - Authenticated Reflected Cross-Site Scripting: The Registrations for the Events Calendar WordPress plugin before 2.7.5 does not escape the v parameter before outputting it back in an attribute, leading to a Reflected Cross-Site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24876"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24876, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24876.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=registrations-for-the-events-calendar(&|$)/ nocase
        $param1 = /(^|[?&;])tab=registrations(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24915_contest_gallery {
    meta:
        attack_type = "cve_2021_24915"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Contest Gallery < 13.1.0.6 - SQL injection: The plugin does not have capability checks and does not sanitise or escape the cg-search-user-name-original parameter before using it in a SQL statement when exporting users from a gallery, which could allow unauthenticated to perform."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24915"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24915, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24915.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])page=contest-gallery\/index\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24926_domain_check {
    meta:
        attack_type = "cve_2021_24926"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Domain Check <1.0.17 - Cross-Site Scripting: WordPress Domain Check plugin before 1.0.17 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the domain parameter before outputting it back in the page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24926"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24926, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24926.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=domain-check-profile(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24934_visual_css_style_editor {
    meta:
        attack_type = "cve_2021_24934"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Visual CSS Style Editor < 7.5.4 - Cross-Site Scripting: The plugin does not sanitise and escape the wyp_page_type parameter before outputting it back in an admin page, leading to a Reflected Cross-Site Scripting issue"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24934"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24934, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24934.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])wyp_mode=single(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24940_persian_woocommerce {
    meta:
        attack_type = "cve_2021_24940"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Persian Woocommerce <=5.8.0 - Cross-Site Scripting: WordPress Persian Woocommerce plugin through 5.8.0 contains a cross-site scripting vulnerability. The plugin does not escape the s parameter before outputting it back in an attribute in the admin dashboard. An."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24940.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=persian-wc(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24943_registrations_for_the_events_c {
    meta:
        attack_type = "cve_2021_24943"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Registrations for the Events Calendar < 2.7.6 - SQL Injection: The Registrations for the Events Calendar WordPress plugin before 2.7.6 does not sanitise and escape the event_id in the rtec_send_unregister_link AJAX action (available to both unauthenticated and authenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24943.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])event_id=3 AND \(SELECT 1874 FROM \(SELECT\(SLEEP\(5\)\)\)vNpy\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24947_responsive_vector_maps {
    meta:
        attack_type = "cve_2021_24947"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Responsive Vector Maps < 6.4.2 - Arbitrary File Read: WordPress Responsive Vector Maps < 6.4.2 contains an arbitrary file read vulnerability because the plugin does not have proper authorization and validation of the rvm_upload_regions_file_path parameter in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24947"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24947, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24947.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=rvm_import_regions(&|$)/ nocase
        $param1 = /(^|[?&;])rvm_upload_regions_file_path=\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24970_all_in_one_video_gallery {
    meta:
        attack_type = "cve_2021_24970"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress All-In-One Video Gallery <2.5.0 - Local File Inclusion: WordPress All-in-One Video Gallery plugin before 2.5.0 is susceptible to local file inclusion. The plugin does not sanitize and validate the tab parameter before using it in a require statement in the admin."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24970"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24970, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24970.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])page=all-in-one-video-gallery(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24979_paid_memberships_pro {
    meta:
        attack_type = "cve_2021_24979"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Paid Memberships Pro < 2.6.6 - Cross-Site Scripting: The Paid Memberships Pro WordPress plugin before 2.6.6 does not escape the s parameter before outputting it back in an attribute in an admin page, leading to a Reflected Cross-Site Scripting"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24979"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24979, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24979.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=pmpro-discountcodes(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_24997_wp_guppy {
    meta:
        attack_type = "cve_2021_24997"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Guppy <=1.1 - Information Disclosure: WordPress Guppy plugin through 1.1 is susceptible to an API disclosure vulnerability. This can allow an attacker to obtain all user IDs and then use them to make API requests to get messages sent between users and/or send messages."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-24997"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24997, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-24997.yaml"
    strings:
        $path0 = /\/wp-json\/guppy\/v2\/load-guppy-users(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_25003_wpcargo_track_trace {
    meta:
        attack_type = "cve_2021_25003"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress WPCargo Track & Trace <6.9.0 - Remote Code Execution: WordPress WPCargo Track & Trace plugin before 6.9.0 is susceptible to remote code execution, The plugin contains a file which can allow an attacker to write a PHP file anywhere on the web server, leading to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25003"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25003, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25003.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/wpcargo/includes/" ascii nocase
        $path1 = /\/wp-content\/plugins\/wpcargo\/includes\/barcode\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sizefactor=\.090909090909(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25032_capabilities {
    meta:
        attack_type = "cve_2021_25032"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PublishPress Capabilities < 2.3.1 - Missing Authorization: The PublishPress Capabilities plugin for WordPress before 2.3.1 does not have proper authorization and CSRF checks when updating settings via the init hook, allowing unauthenticated attackers to update arbitrary blog."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25032"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25032, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25032.yaml"
    strings:
        $param0 = /(^|[?&;])page=pp-capabilities-settings(&|$)/ nocase
        $param1 = /(^|[?&;])all_options=default_role(&|$)/ nocase
        $param2 = /(^|[?&;])default_role=administrator(&|$)/ nocase
        $param3 = /(^|[?&;])page=pp-capabilities(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25033_noptin {
    meta:
        attack_type = "cve_2021_25033"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Noptin < 1.6.5 - Open Redirect: Noptin < 1.6.5 is susceptible to an open redirect vulnerability. The plugin does not validate the 'to' parameter before redirecting the user to its given value, leading to an open redirect issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25033"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25033, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25033.yaml"
    strings:
        $param0 = /(^|[?&;])noptin_ns=email_click(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25052_button_generator {
    meta:
        attack_type = "cve_2021_25052"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Button Generator <2.3.3 - Remote File Inclusion: WordPress Button Generator before 2.3.3 within the wow-company admin menu page allows arbitrary file inclusion with PHP extensions (as well as with data:// or http:// protocols), thus leading to cross-site request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25052"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25052, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25052.yaml"
    strings:
        $param0 = /(^|[?&;])page=wow-company(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25055_feedwordpress {
    meta:
        attack_type = "cve_2021_25055"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress FeedWordPress < 2022.0123 - Authenticated Cross-Site Scripting: The plugin is affected by a cross-site scripting vulnerability within the 'visibility' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25055"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25055, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25055.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=feedwordpress\/syndication\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25063_contact_form_7_skins {
    meta:
        attack_type = "cve_2021_25063"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Contact Form 7 Skins <=2.5.0 - Cross-Site Scripting: WordPress Contact Form 7 Skins plugin 2.5.0 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the tab parameter before outputting it back in an admin page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25063"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25063, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25063.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=cf7skins(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25067_landing_page {
    meta:
        attack_type = "cve_2021_25067"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Landing Page Builder < 1.4.9.6 - Cross-Site Scripting: The Landing Page Builder WordPress plugin before 1.4.9.6 was affected by a reflected XSS in page-builder-add on the ulpb_post admin page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25067"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25067, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25067.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=ulpb_post(&|$)/ nocase
        $param1 = /(^|[?&;])page=page-builder-new-landing-page(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25074_webp_converter_for_media {
    meta:
        attack_type = "cve_2021_25074"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WebP Converter for Media < 4.0.3 - Unauthenticated Open Redirect: WordPress WebP Converter for Media < 4.0.3 contains a file (passthru.php) which does not validate the src parameter before redirecting the user to it, leading to an open redirect issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25074"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25074, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25074.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/webp-converter-for-media\/includes\/passthru\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_25075_duplicate_page_or_post {
    meta:
        attack_type = "cve_2021_25075"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Duplicate Page or Post <1.5.1 - Cross-Site Scripting: WordPress Duplicate Page or Post plugin before 1.5.1 contains a stored cross-site scripting vulnerability. The plugin does not have any authorization and has a flawed cross-site request forgery check in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25075"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25075, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25075.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=wpdevart_duplicate_post_parametrs_save_in_db(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25078_affiliates_manager {
    meta:
        attack_type = "cve_2021_25078"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Affiliates Manager < 2.9.0 - Cross Site Scripting: The plugin does not validate, sanitise and escape the IP address of requests logged by the click tracking feature, allowing unauthenticated attackers to perform Cross-Site Scripting attacks against admin viewing the tracked."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25078"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25078, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25078.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wpam-clicktracking(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25085_woocommerce_products_filter {
    meta:
        attack_type = "cve_2021_25085"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WOOF WordPress plugin - Cross-Site Scripting: The WOOF WordPress plugin does not sanitize or escape the woof_redraw_elements parameter before reflecting it back in an admin page, leading to a reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25085"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25085, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25085.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=woof_draw_products(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25094_wordpress_tatsubuilder_3_3_11 {
    meta:
        attack_type = "cve_2021_25094"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress Tatsubuilder <= 3.3.11 - Remote Code Execution: An unrestricted file upload in WordPress Tatsubuilder plugin version <= 3.3.11 enables an unauthenticated attacker to perform a remote code execution (RCE) on the server host due to multiple weaknesses in the font import."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25094"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25094, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25094.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/typehub/custom/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_25099_givewp {
    meta:
        attack_type = "cve_2021_25099"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress GiveWP <2.17.3 - Cross-Site Scripting: WordPress GiveWP plugin before 2.17.3 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape the form_id parameter before returning it in the response of an unauthenticated request via the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25099"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25099, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25099.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=give_checkout_login(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25120_easy_social_feed {
    meta:
        attack_type = "cve_2021_25120"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Easy Social Feed < 6.2.7 - Cross-Site Scripting: Easy Social Feed < 6.2.7 is susceptible to reflected cross-site scripting because the plugin does not sanitize and escape a parameter before outputting it back in an admin dashboard page, leading to it being executed in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25120"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25120, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25120.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=easy-facebook-likebox(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25161_aruba_instant_access_point {
    meta:
        attack_type = "cve_2021_25161"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Aruba Instant Access Point (IAP) - Cross-Site Scripting: A remote cross-site scripting (xss) vulnerability was discovered in some Aruba Instant Access Point (IAP) products in version(s): Aruba Instant 6.4.x: 6.4.4.8-4.2.4.17 and below; Aruba Instant 6.5.x: 6.5.4.18 and below."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25161.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/swarm\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])opcode=cp_preview(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_25299_nagios_xi {
    meta:
        attack_type = "cve_2021_25299"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Nagios XI 5.7.5 - Cross-Site Scripting: Nagios XI 5.7.5 contains a cross-site scripting vulnerability in the file /usr/local/nagiosxi/html/admin/sshterm.php, due to improper sanitization of user-controlled input. A maliciously crafted URL, when clicked by an admin user, can be."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-25299"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25299, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25299.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/nagiosxi\/admin\/sshterm\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26072_confluence_server {
    meta:
        attack_type = "cve_2021_26072"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Confluence < 5.8.6 - Server-Side Request Forgery: Confluence Server and Data Center before 5.8.6 contain a blind server-side request forgery caused by the WidgetConnector plugin, letting remote attackers manipulate internal network resources, exploit requires network."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26072"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26072, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26072.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/rest\/sharelinks\/1\.0\/link(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26247_cacti {
    meta:
        attack_type = "cve_2021_26247"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cacti - Cross-Site Scripting: Cacti contains a cross-site scripting vulnerability via 'http://<CACTI_SERVER>/auth_changepassword.php?ref=<script>alert(1)</script>' which can successfully execute the JavaScript payload present in the 'ref' URL parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26247"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26247, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26247.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/auth_changepassword\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26294_aurora {
    meta:
        attack_type = "cve_2021_26294"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AfterLogic Aurora and WebMail Pro < 7.7.9 - Information Disclosure: AfterLogic Aurora and WebMail Pro products with 7.7.9 and all lower versions are affected by this vulnerability, simply sending an HTTP GET request to WebDAV EndPoint with built-in caldav_public_user@localhost."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26294"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26294, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26294.yaml"
    strings:
        $path0 = "/dav/server.php/files/personal/../../../../data/settings/settings.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26598_impresscms {
    meta:
        attack_type = "cve_2021_26598"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ImpressCMS <1.4.3 - Incorrect Authorization: ImpressCMS before 1.4.3 is susceptible to incorrect authorization via include/findusers.php. An attacker can provide a security token and potentially obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26598"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26598, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26598.yaml"
    strings:
        $path0 = /\/include\/findusers\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26702_eprints {
    meta:
        attack_type = "cve_2021_26702"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EPrints 3.4.2 - Cross-Site Scripting: EPrints 3.4.2 contains a reflected cross-site scripting vulnerability in the dataset parameter to the cgi/dataset_ dictionary URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26702"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26702, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26702.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/cgi\/dataset_dictionary(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_26812_meet {
    meta:
        attack_type = "cve_2021_26812"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Moodle Jitsi Meet 2.7-2.8.3 - Cross-Site Scripting: Moodle Jitsi Meet 2.7 through 2.8.3 plugin contains a cross-site scripting vulnerability via the 'sessionpriv.php' module. This allows attackers to craft a malicious URL, which when clicked on by users, can inject JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26812"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26812, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26812.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mod\/jitsi\/sessionpriv\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])avatar=https:\/\/\/user\/pix\.php\/498\/f1\.jpg(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_26947_odoo {
    meta:
        attack_type = "cve_2021_26947"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Odoo <= 15.0 - Cross-Site Scripting: A cross-site scripting (XSS) vulnerability in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows remote attackers to inject arbitrary web scripts into the browser of a victim via a crafted link. This issue could lead."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-26947"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26947, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-26947.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/web\/reset_password(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27124_doctor_appointment_system {
    meta:
        attack_type = "cve_2021_27124"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Doctor Appointment System 1.0 - SQL Injection: SQL injection in the expertise parameter in search_result.php in Doctor Appointment System v1.0."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27124"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27124, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27124.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/patient\/search_result\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27309_clansphere {
    meta:
        attack_type = "cve_2021_27309"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Clansphere CMS 2011.4 - Cross-Site Scripting: Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the 'module' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27309"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27309, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27309.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mods\/clansphere\/lang_modvalidate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27310_clansphere {
    meta:
        attack_type = "cve_2021_27310"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Clansphere CMS 2011.4 - Cross-Site Scripting: Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the 'language' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27310"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27310, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27310.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/clansphere\/mods\/clansphere\/lang_modvalidate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27520_fudforum {
    meta:
        attack_type = "cve_2021_27520"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FUDForum 3.1.0 - Cross-Site Scripting: FUDForum 3.1.0 contains a cross-site scripting vulnerability. An attacker can inject JavaScript via index.php in the author parameter, thereby possibly stealing cookie-based authentication credentials and launching other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27520"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27520, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27520.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/forum\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27561_device_management {
    meta:
        attack_type = "cve_2021_27561"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "YeaLink DM 3.6.0.20 - Remote Command Injection: Yealink Device Management (DM) 3.6.0.20 allows command injection as root via the /sm/api/v1/firewall/zone/services URI, without authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27561"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27561, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27561.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/premise\/front\/getPingData(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27670_appspace {
    meta:
        attack_type = "cve_2021_27670"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Appspace 6.2.4 - Server-Side Request Forgery: Appspace 6.2.4 allows SSRF via the api/v1/core/proxy/jsonprequest url parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27670"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27670, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27670.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/api\/v1\/core\/proxy\/jsonprequest(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27850_tapestry {
    meta:
        attack_type = "cve_2021_27850"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Tapestry - Remote Code Execution: Apache Tapestry contains a critical unauthenticated remote code execution vulnerability. Affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. Note that this vulnerability is a bypass of the fix for CVE-2019-0195. Before that fix it."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27850"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27850, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27850.yaml"
    strings:
        $path0 = "/assets/app/something/services/AppModule.class/" ascii nocase
        $path1 = "/services/AppModule.class/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27856_warp_firmware {
    meta:
        attack_type = "cve_2021_27856"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FatPipe WARP/IPVPN/MPVPN - Backdoor Account: FatPipe WARP, IPVPN, and MPVPN software prior to versions 10.1.2r60p91 and 10.2.2r42 contain an account named 'cmuser' with administrative privileges and no password, letting attackers gain unauthorized admin access, exploit requires."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27856"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27856, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27856.yaml"
    strings:
        $path0 = /\/fpui\/loginServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27905_solr {
    meta:
        attack_type = "cve_2021_27905"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Solr <=8.8.1 - Server-Side Request Forgery: Apache Solr versions 8.8.1 and prior contain a server-side request forgery vulnerability. The ReplicationHandler (normally registered at '/replication' under a Solr core) in Apache Solr has a 'masterUrl' (also 'leaderUrl'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27905"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27905, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27905.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])command=fetchindex(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_27931_lumis_experience_platform {
    meta:
        attack_type = "cve_2021_27931"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LumisXP <10.0.0 - Blind XML External Entity Attack: LumisXP (aka Lumis Experience Platform) before 10.0.0 allows unauthenticated blind XML external entity (XXE) attacks via an API request to PageControllerXml.jsp. One can send a request crafted with an XXE payload and achieve."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27931"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27931, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27931.yaml"
    strings:
        $path0 = /\/lumis\/portal\/controller\/xml\/PageControllerXml\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_27964_sonlogger {
    meta:
        attack_type = "cve_2021_27964"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SonLogger - Arbitrary File Upload: SonLogger before 6.4.1 is affected by Unauthenticated Arbitrary File Upload. An attacker can send a POST request to /Config/SaveUploadedHotspotLogoFile without any authentication or session header. There is no check for the file extension or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-27964"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27964, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-27964.yaml"
    strings:
        $path0 = "/Assets/temp/hotspot/img/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_28150_h8922_firmware {
    meta:
        attack_type = "cve_2021_28150"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hongdian H8922 3.0.5 - Information Disclosure: Hongdian H8922 3.0.5 is susceptible to information disclosure. An attacker can access cli.conf (with the administrator password and other sensitive data) via /backup2.cgi and thereby possibly obtain sensitive information, modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28150.yaml"
    strings:
        $path0 = /\/backup2\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_28151_h8922_firmware {
    meta:
        attack_type = "cve_2021_28151"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongdian H8922 3.0.5 - Remote Command Injection: Hongdian H8922 3.0.5 devices are susceptible to remote command injection via shell metacharacters into the ip-address (a/k/a Destination) field to the tools.cgi ping command, which is accessible with the username guest and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28151"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28151, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28151.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/tools\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])op_type=ping(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_28377_chronoforums {
    meta:
        attack_type = "cve_2021_28377"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! ChronoForums 2.0.11 - Local File Inclusion: Joomla! ChronoForums 2.0.11 avatar function is vulnerable to local file inclusion through unauthenticated path traversal attacks. This enables an attacker to read arbitrary files, for example the Joomla! configuration file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28377"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28377, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28377.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/index.php/component/chronoforums2/profiles/avatar/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_28480_exchange_server {
    meta:
        attack_type = "cve_2021_28480"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Microsoft Exchange - Pre-Auth SSRF / ACL Bypass (ProxyNotFound): Microsoft Exchange Server contains a remote code execution caused by improper input validation in the server component, letting remote attackers execute arbitrary code, exploit requires network access to the server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28480"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28480, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28480.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/owa/calendar/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_28481_exchange_server {
    meta:
        attack_type = "cve_2021_28481"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Microsoft Exchange - Pre-Auth SSRF / ACL Bypass (ProxyNotFound): Microsoft Exchange Server contains a remote code execution caused by improper input validation in the server component, letting remote attackers execute arbitrary code, exploit requires network access to the server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28481"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28481, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28481.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/ews\/wssecurity(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_28937_wireless_n_wifi_repeater {
    meta:
        attack_type = "cve_2021_28937"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Acexy Wireless-N WiFi Repeater REV 1.0 - Repeater Password Disclosure: Acexy Wireless-N WiFi Repeater REV 1.0 is vulnerable to password disclosure because the password.html page of the web management interface contains the administrator account password in plaintext."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-28937"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28937, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-28937.yaml"
    strings:
        $path0 = /\/password\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_29156_openam {
    meta:
        attack_type = "cve_2021_29156"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LDAP Injection In OpenAM: OpenAM contains an LDAP injection vulnerability. When a user tries to reset his password, they are asked to enter username, and then the backend validates whether the user exists or not through an LDAP query. If the user exists, the password reset."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-29156"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29156, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-29156.yaml"
    strings:
        $path0 = /\/OpenAM-11\.0\.0\/ui\/PWResetUserValidation(\/|;|$)/ nocase
        $path1 = /\/ui\/PWResetUserValidation(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_29203_edgeline_infrastructure_manage {
    meta:
        attack_type = "cve_2021_29203"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "HPE Edgeline Infrastructure Manager <1.22 - Authentication Bypass: HPE Edgeline Infrastructure Manager, also known as HPE Edgeline Infrastructure Management Software, prior to version 1.22 contains an authentication bypass vulnerability which could be remotely exploited to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-29203"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29203, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-29203.yaml"
    strings:
        $path0 = "/redfish/v1/SessionService/ResetPassword/1/" ascii nocase
        $path1 = "/redfish/v1/SessionService/Sessions/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_29442_nacos {
    meta:
        attack_type = "cve_2021_29442"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nacos <1.4.1 - Authentication Bypass: Nacos before version 1.4.1 is vulnerable to authentication bypass because the ConfigOpsController lets the user perform management operations like querying the database or even wiping it out. While the /data/remove endpoint is properly."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-29442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-29442.yaml"
    strings:
        $path0 = /\/nacos\/v1\/cs\/ops\/derby(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sql=select st\.tablename from sys\.systables st(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_29484_ghost {
    meta:
        attack_type = "cve_2021_29484"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ghost CMS <=4.32 - Cross-Site Scripting: Ghost CMS 4.0.0 to 4.3.2 contains a DOM cross-site scripting vulnerability. An unused endpoint added during the development of 4.0.0 allows attackers to gain access by getting logged-in users to click a link containing malicious code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-29484"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29484, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-29484.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ghost\/preview(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_29490_jellyfin {
    meta:
        attack_type = "cve_2021_29490"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jellyfin 10.7.2 - Server Side Request Forgery: Jellyfin is a free software media system. Versions 10.7.2 and below are vulnerable to unauthenticated Server-Side Request Forgery (SSRF) attacks via the imageUrl parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-29490"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29490, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-29490.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/Images\/Remote(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_3002_seo_panel {
    meta:
        attack_type = "cve_2021_3002"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Seo Panel 4.8.0 - Cross-Site Scripting: Seo Panel 4.8.0 contains a reflected cross-site scripting vulnerability via the seo/seopanel/login.php?sec=forgot email parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3002"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3002, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3002.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/seo\/seopanel\/login\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sec=requestpass(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_30116_virtual_system_administrator {
    meta:
        attack_type = "cve_2021_30116"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Kaseya VSA < 9.5.7 - Credential Disclosure via Windows Agent: Kaseya VSA before 9.5.7 allows credential disclosure, as exploited in the wild in July 2021. By default Kaseya VSA on premise offers a download page where the clients for the installation can be downloaded. The."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30116"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30116, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30116.yaml"
    strings:
        $path0 = /\/mkDefault\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_30118_vsa {
    meta:
        attack_type = "cve_2021_30118"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kaseya VSA < 9.5.7 - Arbitrary File Upload to Remote Code Execution: An attacker can upload files with the privilege of the Web Server process for Kaseya VSA Unified Remote Monitoring & Management (RMM) 9.5.4.2149 and subsequently use these files to execute asp commands The api."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30118"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30118, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30118.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/SystemTab\/uploader\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])__RequestValidationToken=ac1906a5-d511-47e3-8500-47cc4b0ec219(&|$)/ nocase
        $param1 = /(^|[?&;])byte\[\] hash=MD5\.Create\(\)\.ComputeHash\(bytes\);(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_30134_php_curl_class {
    meta:
        attack_type = "cve_2021_30134"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Php-mod/curl Library <2.3.2 - Cross-Site Scripting: Php-mod/curl library before 2.3.2 contains a cross-site scripting vulnerability via the post_file_path_upload.php key parameter and the POST data to post_multidimensional.php. An attacker can inject arbitrary script, which can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30134.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/vendor\/curl\/curl\/tests\/server\/php-curl-test\/post_file_path_upload\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_3019_lanproxy {
    meta:
        attack_type = "cve_2021_3019"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ffay lanproxy Directory Traversal: ffay lanproxy 0.1 is susceptible to a directory traversal vulnerability that could let attackers read /../conf/config.properties to obtain credentials for a connection to the intranet."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3019"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3019, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3019.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/\.\.\/conf\/config\.properties(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_30213_knowage {
    meta:
        attack_type = "cve_2021_30213"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Knowage Suite 7.3 - Cross-Site Scripting: Knowage Suite 7.3 contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can inject arbitrary web script in '/servlet/AdapterHTTP' via the 'targetService' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30213"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30213, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30213.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/knowage\/servlet\/AdapterHTTP(\/|;|$)/ nocase
        $param0 = /(^|[?&;])Page=LoginPage(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_30461_voipmonitor {
    meta:
        attack_type = "cve_2021_30461"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VoipMonitor <24.61 - Remote Code Execution: VoipMonitor prior to 24.61 is susceptible to remote code execution vulnerabilities because of its use of user supplied data via its web interface, allowing remote unauthenticated users to trigger a remote PHP code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30461"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30461, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30461.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])recheck=Recheck(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_30497_avalanche {
    meta:
        attack_type = "cve_2021_30497"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ivanti Avalanche 6.3.2 - Local File Inclusion: Ivanti Avalanche 6.3.2 is vulnerable to local file inclusion because it allows remote unauthenticated user to access files that reside outside the 'image' folder."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-30497"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30497, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-30497.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/AvalancheWeb\/image(\/|;|$)/ nocase
        $param0 = /(^|[?&;])imageFilePath=C:\/windows\/win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_31195_exchange_server {
    meta:
        attack_type = "cve_2021_31195"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microsoft Exchange Server - Cross-Site Scripting: Microsoft Exchange Server, or OWA, is vulnerable to a cross-site scripting vulnerability in refurl parameter of frowny.asp."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31195"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31195, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31195.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/owa\/auth\/frowny\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])et=ServerError(&|$)/ nocase
        $param1 = /(^|[?&;])esrc=MasterPage(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_3152_integration {
    meta:
        attack_type = "cve_2021_3152"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Home Assistant HACS - Local File Inclusion: Home Assistant before 2021.1.3 lacks a protection layer against directory-traversal attacks in custom integrations, letting attackers access arbitrary files, exploit requires attacker to deploy malicious custom integration."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3152"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3152, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3152.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/hacsfiles\/\.\.\/\.\.\/configuration\.yaml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_31537_sis_rewe_go {
    meta:
        attack_type = "cve_2021_31537"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SIS Informatik REWE GO SP17 <7.7 - Cross-Site Scripting: SIS Informatik REWE GO SP17 before 7.7 contains a cross-site scripting vulnerability via rewe/prod/web/index.php (affected parameters are config, version, win, db, pwd, and user) and /rewe/prod/web/rewe_go_check.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31537"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31537, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31537.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/rewe\/prod\/web\/rewe_go_check\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_31581_ova_appliance {
    meta:
        attack_type = "cve_2021_31581"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Akkadian Provisioning Manager - Information Disclosure: Akkadian Provisioning Manager is susceptible to information disclosure. The restricted shell provided can be escaped by abusing the Edit MySQL Configuration command. This command launches a standard VI editor interface."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31581"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31581, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31581.yaml"
    strings:
        $path0 = /\/pme\/database\/pme\/phinx\.yml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_31589_appliance_base_software {
    meta:
        attack_type = "cve_2021_31589"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "BeyondTrust Secure Remote Access Base <=6.0.1 - Cross-Site Scripting: BeyondTrust Secure Remote Access Base through 6.0.1 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31589"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31589, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31589.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/appliance\/login\.ns(\/|;|$)/ nocase
        $param0 = /(^|[?&;])login\[submit\]=Change Password(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_31602_vantara_pentaho {
    meta:
        attack_type = "cve_2021_31602"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hitachi Vantara Pentaho/Business Intelligence Server - Authentication Bypass: Hitachi Vantara Pentaho through 9.1 and Pentaho Business Intelligence Server through 7.x are vulnerable to authentication bypass. The Security Model has different layers of Access Control. One of."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31602"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31602, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31602.yaml"
    strings:
        $path0 = /\/pentaho\/api\/userrolelist\/systemRoles(\/|;|$)/ nocase
        $path1 = /\/api\/userrolelist\/systemRoles(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_31755_ac11_firmware {
    meta:
        attack_type = "cve_2021_31755"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Tenda Router AC11 - Remote Command Injection: Tenda Router AC11 is susceptible to remote command injection vulnerabilities in the web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31755"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31755, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31755.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goform\/setmac(\/|;|$)/ nocase
        $param0 = /(^|[?&;])module1=wifiBasicCfg(&|$)/ nocase
        $param1 = /(^|[?&;])wifiSSID=Tenda_B0E040(&|$)/ nocase
        $param2 = /(^|[?&;])wifiSecurityMode=WPAWPA2\/AES(&|$)/ nocase
        $param3 = /(^|[?&;])wifiPwd=Password12345(&|$)/ nocase
        $param4 = /(^|[?&;])wifiSSID_5G=Tenda_B0E040_5G(&|$)/ nocase
        $param5 = /(^|[?&;])wifiSecurityMode_5G=WPAWPA2\/AES(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_31856_meshery {
    meta:
        attack_type = "cve_2021_31856"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Layer5 Meshery 0.5.2 - SQL Injection: Layer5 Meshery 0.5.2 contains a SQL injection vulnerability in the REST API that allows an attacker to execute arbitrary SQL commands via the /experimental/patternfiles endpoint (order parameter in GetMesheryPatterns in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-31856"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-31856, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-31856.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/experimental\/patternfile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_32030_gt_ac2900_firmware {
    meta:
        attack_type = "cve_2021_32030"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "ASUS GT-AC2900 - Authentication Bypass: ASUS GT-AC2900 devices before 3.0.0.4.386.42643 allows authentication bypass when processing remote input from an unauthenticated user, leading to unauthorized access to the administrator application. This relates to handle_request in."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32030"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32030, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32030.yaml"
    strings:
        $path0 = /\/appGet\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])hook=get_cfg_clientlist\(\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_3239_e_learning_system_1_0 {
    meta:
        attack_type = "cve_2021_3239"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "E-Learning System 1.0 - SQL Injection: E-Learning System 1.0 contains an unauthenticated SQL injection caused by unsanitized input, letting remote attackers execute arbitrary code on the server and gain a reverse shell, exploit requires no authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3239"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3239, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3239.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/caiwl\/lesson\.php(\/|;|$)/ nocase
        $path1 = /\/lesson\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_32648_october {
    meta:
        attack_type = "cve_2021_32648"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "OctoberCMS - Account Takeover: octobercms in a CMS platform based on the Laravel PHP Framework. In affected versions of the october/system package an attacker can request an account password reset and then gain access to the account using a specially crafted request. The issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32648"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32648, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32648.yaml"
    strings:
        $path0 = /\/backend\/backend\/auth\/restore(\/|;|$)/ nocase
        $path1 = "/backend/backend/auth/reset/1/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_32682_elfinder {
    meta:
        attack_type = "cve_2021_32682"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "elFinder 2.1.58 - Remote Code Execution: elFinder 2.1.58 is impacted by multiple remote code execution vulnerabilities that could allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32682"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32682, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32682.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/admin\/elfinder\/elfinder-cke\.html(\/|;|$)/ nocase
        $path1 = /\/assets\/backend\/elfinder\/elfinder-cke\.html(\/|;|$)/ nocase
        $path2 = /\/assets\/elFinder-2\.1\.9\/elfinder\.html(\/|;|$)/ nocase
        $path3 = /\/assets\/elFinder\/elfinder\.html(\/|;|$)/ nocase
        $path4 = /\/backend\/elfinder\/elfinder-cke\.html(\/|;|$)/ nocase
        $path5 = /\/elfinder\/elfinder-cke\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_32789_woocommerce_blocks {
    meta:
        attack_type = "cve_2021_32789"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WooCommerce Blocks 2.5 to 5.5 - Unauthenticated SQL Injection: woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32789"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32789, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32789.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])rest_route=\/wc\/store\/products\/collection-data(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_32820_express_handlebars {
    meta:
        attack_type = "cve_2021_32820"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Express-handlebars - Local File Inclusion: Express-handlebars is susceptible to local file inclusion because it mixes pure template data with engine configuration options through the Express render API. More specifically, the layout parameter may trigger file disclosure."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32820"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32820, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32820.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])layout=\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_32853_erxes {
    meta:
        attack_type = "cve_2021_32853"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Erxes <0.23.0 - Cross-Site Scripting: Erxes before 0.23.0 contains a cross-site scripting vulnerability. The value of topicID parameter is not escaped and is triggered in the enclosing script tag."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-32853"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32853, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-32853.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/widgets\/knowledgebase(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33221_ruckus_iot_controller {
    meta:
        attack_type = "cve_2021_33221"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CommScope Ruckus IoT Controller - Information Disclosure: CommScope Ruckus IoT Controller is susceptible to information disclosure vulnerabilities because a 'service details' API endpoint discloses system and configuration information to an attacker without requiring."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33221"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33221, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33221.yaml"
    strings:
        $path0 = /\/service\/v1\/service-details(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33357_raspap {
    meta:
        attack_type = "cve_2021_33357"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "RaspAP <=2.6.5 - Remote Command Injection: RaspAP 2.6 to 2.6.5 allows unauthenticated attackers to execute arbitrary OS commands via the 'iface' GET parameter in /ajax/networking/get_netcfg.php, when the 'iface' parameter value contains special characters such as ';'."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33357"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33357, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33357.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ajax\/networking\/get_netcfg\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33544_g_cam_ebc_2110 {
    meta:
        attack_type = "cve_2021_33544"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Geutebruck - Remote Command Injection: Geutebruck is susceptible to multiple vulnerabilities its web-based management interface that could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33544"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33544, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33544.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/uapi-cgi\/certmngr\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=createselfcert(&|$)/ nocase
        $param1 = /(^|[?&;])local=anything(&|$)/ nocase
        $param2 = /(^|[?&;])organization=anything(&|$)/ nocase
        $param3 = /(^|[?&;])organizationunit=anything(&|$)/ nocase
        $param4 = /(^|[?&;])commonname=anything(&|$)/ nocase
        $param5 = /(^|[?&;])type=anything(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_33564_dragonfly {
    meta:
        attack_type = "cve_2021_33564"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ruby Dragonfly <1.4.0 - Remote Code Execution: Ruby Dragonfly before 1.4.0 contains an argument injection vulnerability that allows remote attackers to read and write to arbitrary files via a crafted URL when the verify_url option is disabled. This may lead to code execution.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33564"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33564, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33564.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/system\/images\/W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ==(\/|;|$)/ nocase
        $path1 = /\/system\/refinery\/images\/W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ==(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33690_netweaver_development_infrastr {
    meta:
        attack_type = "cve_2021_33690"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SAP NetWeaver Development Infrastructure - Server Side Request Forgery: Server-Side Request Forgery (SSRF) vulnerability has been detected in the SAP NetWeaver Development Infrastructure Component Build Service versions - 7.11, 7.20, 7.30, 7.31, 7.40, 7.50The SAP NetWeaver."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33690"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33690, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33690.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/tc\.CBS\.Appl\/tcspseudo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_3374_shiny_server {
    meta:
        attack_type = "cve_2021_3374"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rstudio Shiny Server <1.5.16 - Local File Inclusion: Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage. This can be exploited by appending an encoded slash to the URL."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3374"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3374, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3374.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/sample-apps/hello/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33766_exchange_server {
    meta:
        attack_type = "cve_2021_33766"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Microsoft Exchange - Authentication Bypass: Microsoft Exchange Server Information Disclosure Vulnerability. This vulnerability enables an attacker to bypass authentication and gain access to the Exchange Server's internal."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33766"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33766, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33766.yaml"
    strings:
        $path0 = /\/PersonalSettings\/HomePage\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_3378_fortilogger {
    meta:
        attack_type = "cve_2021_3378"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FortiLogger 4.4.2.2 - Arbitrary File Upload: FortiLogger 4.4.2.2 is affected by arbitrary file upload issues. Attackers can send a 'Content-Type: image/png' header to Config/SaveUploadedHotspotLogoFile and then Assets/temp/hotspot/img/logohotspot.asp."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3378"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3378, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3378.yaml"
    strings:
        $path0 = /\/Assets\/temp\/hotspot\/img\/logohotspot\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_33807_gespage {
    meta:
        attack_type = "cve_2021_33807"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cartadis Gespage 8.2.1 - Directory Traversal: Cartadis Gespage through 8.2.1 allows Directory Traversal in gespage/doDownloadData and gespage/webapp/doDownloadData."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33807"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33807, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33807.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/gespage\/doDownloadData(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Windows\/debug\/NetSetup\.log(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_33829_drupal_7_ckeditor_xss {
    meta:
        attack_type = "cve_2021_33829"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Drupal 7 CKEditor XSS: CKEditor 4.14.0 through 4.16.x before 4.16.1 contains a reflected cross-site scripting caused by mishandling in comments, letting remote attackers inject executable JavaScript code, exploit requires victim to view malicious content."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33829"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33829, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33829.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])title=XSSTest(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_33851_customize_login_image {
    meta:
        attack_type = "cve_2021_33851"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Customize Login Image <3.5.3 - Cross-Site Scripting: WordPress Customize Login Image plugin prior to 3.5.3 contains a cross-site scripting vulnerability via the custom logo link on the Settings page. This can allow an attacker to steal cookie-based authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33851"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33851, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33851.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=customize-login-image\/customize-login-image-options\.php(&|$)/ nocase
        $param1 = /(^|[?&;])option_page=customize-login-image-settings-group(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_33904_civic_platform {
    meta:
        attack_type = "cve_2021_33904"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Accela Civic Platform <=21.1 - Cross-Site Scripting: Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via the security/hostSignon.do parameter servProvCode."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-33904"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33904, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-33904.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/security\/hostSignon\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_34187_chamilo {
    meta:
        attack_type = "cve_2021_34187"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Chamilo model.ajax.php - SQL Injection: main/inc/ajax/model.ajax.php in Chamilo through 1.11.14 allows SQL Injection via the searchField, filters, or filters2 parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34187"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34187, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34187.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/main\/inc\/ajax\/model\.ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])a=get_sessions_tracking(&|$)/ nocase
        $param1 = /(^|[?&;])searchString=testx(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_34370_civic_platform {
    meta:
        attack_type = "cve_2021_34370"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Accela Civic Platform <=21.1 - Cross-Site Scripting: Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via ssoAdapter/logoutAction.do successURL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34370"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34370, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34370.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ssoAdapter\/logoutAction\.do(\/|;|$)/ nocase
        $param0 = /(^|[?&;])servProvCode=SAFVC(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_34427_business_intelligence_and_repo {
    meta:
        attack_type = "cve_2021_34427"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Eclipse BIRT Viewer - Remote Code Execution: Eclipse BIRT versions 4.8.0 and earlier contain a JSP injection caused by query parameters, letting remote attackers create and access malicious JSP files in the viewer directory, exploit requires sending crafted query parameters."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34427"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34427, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34427.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])__report=test\.rptdesign(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_34429_jetty {
    meta:
        attack_type = "cve_2021_34429"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Eclipse Jetty - Information Disclosure: Eclipse Jetty 9.4.37-9.4.42, 10.0.1-10.0.5 and 11.0.1-11.0.5 are susceptible to improper authorization. URIs can be crafted using some encoded characters to access the content of the WEB-INF directory and/or bypass some security."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34429"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34429, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34429.yaml"
    strings:
        $path0 = /\/%u002e\/WEB-INF\/web\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_34622_profilepress {
    meta:
        attack_type = "cve_2021_34622"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress ProfilePress <= 3.1.3 - Privilege Escalation: ProfilePress plugin before 3.1.4 allows privilege escalation. Due to insufficient validation in the profile update functionality, authenticated users can supply arbitrary usermeta fields, including `wp_capabilities`."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34622"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34622, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34622.yaml"
    strings:
        $path0 = "/account/edit-profile/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_34640_securimage_wp_fixed {
    meta:
        attack_type = "cve_2021_34640"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Securimage-WP-Fixed <=3.5.4 - Cross-Site Scripting: WordPress Securimage-WP-Fixed plugin 3.5.4 and prior contains a cross-site scripting vulnerability due to the use of $_SERVER['PHP_SELF'] in the ~/securimage-wp.php file, which allows attackers to inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34640.yaml"
    strings:
        $param0 = /(^|[?&;])page=securimage-wp-options\/(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_34643_skaut_bazar {
    meta:
        attack_type = "cve_2021_34643"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Skaut Bazar <1.3.3 - Cross-Site Scripting: WordPress Skaut Bazar plugin before 1.3.3 contains a reflected cross-site scripting vulnerability due to the use of $_SERVER['PHP_SELF'] in the ~/skaut-bazar.php file, which allows attackers to inject arbitrary web scripts."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-34643"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34643, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-34643.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=skatubazar_option(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_35250_serv_u {
    meta:
        attack_type = "cve_2021_35250"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SolarWinds Serv-U 15.3 - Directory Traversal: SolarWinds Serv-U 15.3 is susceptible to local file inclusion, which may allow an attacker access to installation and server files and also make it possible to obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35250"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35250, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35250.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])InternalFile=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Windows\/win\.ini(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_35323_bludit {
    meta:
        attack_type = "cve_2021_35323"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bludit 3.13.1 - Cross Site Scripting: Cross Site Scripting (XSS) vulnerability exists in bludit 3-13-1 via the username in admin/login"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35323"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35323, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35323.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/bludit\/admin\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_35336_ip_audtio_gateway {
    meta:
        attack_type = "cve_2021_35336"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tieline IP Audio Gateway <=2.6.4.8 - Unauthorized Remote Admin Panel Access: Tieline IP Audio Gateway 2.6.4.8 and below is affected by a vulnerability in the web administrative interface that could allow an unauthenticated user to access a sensitive part of the system with a."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35336"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35336, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35336.yaml"
    strings:
        $path0 = /\/api\/get_device_details(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_35380_termtalk_server {
    meta:
        attack_type = "cve_2021_35380"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TermTalk Server 3.24.0.2 - Local File Inclusion: TermTalk Server (TTServer) 3.24.0.2 is vulnerable to file inclusion which allows unauthenticated malicious user to gain access to the files on the remote system by providing the relative path of the file they want to retrieve."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35380.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])valore=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/windows\/win\.ini(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_35464_am {
    meta:
        attack_type = "cve_2021_35464"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "ForgeRock OpenAM <7.0 - Remote Code Execution: ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35464"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35464, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35464.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/openam\/oauth2\/\.\.;\/ccversion\/Version(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_35587_access_manager {
    meta:
        attack_type = "cve_2021_35587"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Oracle Access Manager - Remote Code Execution: The Oracle Access Manager portion of Oracle Fusion Middleware (component: OpenSSO Agent) is vulnerable to remote code execution. Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. This is an easily."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-35587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35587, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-35587.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/oam\/server\/opensso\/sessionservice(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_3577_halo_camera_firmware {
    meta:
        attack_type = "cve_2021_3577"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Motorola Baby Monitors - Remote Command Execution: Motorola Baby Monitors contains multiple interface vulnerabilities could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3577"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3577, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3577.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=command(&|$)/ nocase
        $param1 = /(^|[?&;])command=set_city_timezone(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_36380_sureline {
    meta:
        attack_type = "cve_2021_36380"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Sunhillo SureLine <8.7.0.1.1 - Unauthenticated OS Command Injection: Sunhillo SureLine <8.7.0.1.1 is vulnerable to OS command injection. The /cgi/networkDiag.cgi script directly incorporated user-controllable parameters within a shell command, allowing an attacker to manipulate."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-36380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36380.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi\/networkDiag\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_36450_workforce_optimization {
    meta:
        attack_type = "cve_2021_36450"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Verint Workforce Optimization 15.2.8.10048 - Cross-Site Scripting: Verint Workforce Optimization 15.2.8.10048 contains a cross-site scripting vulnerability via the control/my_notifications NEWUINAV parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-36450"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36450, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36450.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wfo\/control\/signin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_36748_blog {
    meta:
        attack_type = "cve_2021_36748"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PrestaHome Blog for PrestaShop <1.7.8 - SQL Injection: PrestaHome Blog for PrestaShop prior to version 1.7.8 is vulnerable to a SQL injection (blind) via the sb_category parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-36748"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36748, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36748.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/module\/ph_simpleblog\/list(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_36873_iq_block_country {
    meta:
        attack_type = "cve_2021_36873"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress iQ Block Country <=1.2.11 - Cross-Site Scripting: WordPress iQ Block Country plugin 1.2.11 and prior contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-36873"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36873, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36873.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=iq-block-country\/libs\/blockcountry-settings\.php(&|$)/ nocase
        $param1 = /(^|[?&;])option_page=iqblockcountry-settings-group(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_36888_wordpress_image_hover_ultimate {
    meta:
        attack_type = "cve_2021_36888"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Image Hover Ultimate - Unauthenticated Settings Update: Unauthenticated Arbitrary Options Update vulnerability leading to full website compromise discovered in Image Hover Effects Ultimate (versions <= 9.6.1) WordPress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-36888"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36888, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36888.yaml"
    strings:
        $path0 = /\/wp-json\/ImageHoverUltimate\/v1\/oxi_settings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37216_xn8024r_firmware {
    meta:
        attack_type = "cve_2021_37216"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "QSAN Storage Manager <3.3.3 - Cross-Site Scripting: QSAN Storage Manager before 3.3.3 contains a reflected cross-site scripting vulnerability. Header page parameters do not filter special characters. Remote attackers can inject JavaScript to access and modify specific data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37216"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37216, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37216.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/http_header\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37304_jeecg {
    meta:
        attack_type = "cve_2021_37304"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jeecg Boot <= 2.4.5 - Information Disclosure: An Insecure Permissions issue in jeecg-boot 2.4.5 allows unauthenticated remote attackers to gain escalated privilege and view sensitive information via the httptrace interface."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37304"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37304, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37304.yaml"
    strings:
        $path0 = "/jeecg-boot/actuator/httptrace/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37305_jeecg {
    meta:
        attack_type = "cve_2021_37305"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jeecg Boot <= 2.4.5 - Sensitive Information Disclosure: Jeecg Boot <= 2.4.5 API interface has unauthorized access and leaks sensitive information such as email,phone and Enumerate usernames that exist in the system."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37305.yaml"
    strings:
        $path0 = /\/jeecg-boot\/sys\/user\/querySysUser(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37415_manageengine_servicedesk_plus {
    meta:
        attack_type = "cve_2021_37415"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zoho ManageEngine ServiceDesk Plus - Authentication Bypass: Zoho ManageEngine ServiceDesk Plus before 11302 is vulnerable to authentication bypass that allows a few REST-API URLs without authentication."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37415"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37415, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37415.yaml"
    strings:
        $path0 = /\/\.\.\/announcements(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37416_manageengine_adselfservice_plu {
    meta:
        attack_type = "cve_2021_37416"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zoho ManageEngine ADSelfService Plus <=6103 - Cross-Site Scripting: Zoho ManageEngine ADSelfService Plus 6103 and prior contains a reflected cross-site scripting vulnerability on the loadframe page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37416"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37416, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37416.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/LoadFrame(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37538_smartblog {
    meta:
        attack_type = "cve_2021_37538"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop SmartBlog <4.0.6 - SQL Injection: PrestaShop SmartBlog by SmartDataSoft < 4.0.6 is vulnerable to a SQL injection vulnerability in the blog archive functionality."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37538"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37538, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37538.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/module\/smartblog\/archive(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37580_shenyu {
    meta:
        attack_type = "cve_2021_37580"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache ShenYu Admin JWT - Authentication Bypass: Apache ShenYu 2.3.0 and 2.4.0 allow Admin access without proper authentication. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37580"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37580, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37580.yaml"
    strings:
        $path0 = /\/dashboardUser(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37589_cobranca {
    meta:
        attack_type = "cve_2021_37589"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Virtua Software Cobranca <12R - Blind SQL Injection: Virtua Cobranca before 12R allows blind SQL injection on the login page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37589"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37589, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37589.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/controller\/origemdb\.php(\/|;|$)/ nocase
        $path1 = /\/controller\/login\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])idselorigem=ATIVOS(&|$)/ nocase
        $param1 = /(^|[?&;])acao=autenticar(&|$)/ nocase
        $param2 = /(^|[?&;])tipousr=Usuario(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_37704_phpfastcache {
    meta:
        attack_type = "cve_2021_37704"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpfastcache - phpinfo Resource Exposure: phpinfo() is susceptible to resource exposure in unprotected composer vendor folders via phpfastcache/phpfastcache."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37704"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37704, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37704.yaml"
    strings:
        $path0 = /\/vendor\/phpfastcache\/phpfastcache\/docs\/examples\/phpinfo\.php(\/|;|$)/ nocase
        $path1 = /\/vendor\/phpfastcache\/phpfastcache\/examples\/phpinfo\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_37833_hoteldruid {
    meta:
        attack_type = "cve_2021_37833"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hotel Druid 3.0.2 - Cross-Site Scripting: Hotel Druid 3.0.2 contains a cross-site scripting vulnerability in multiple pages which allows for arbitrary execution of JavaScript commands."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-37833"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37833, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-37833.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/visualizza_tabelle\.php(\/|;|$)/ nocase
        $path1 = /\/storia_soldi\.php(\/|;|$)/ nocase
        $path2 = /\/tabella\.php(\/|;|$)/ nocase
        $path3 = /\/crea_modelli\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sel_tab_prenota=tutte(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_38147_holmes {
    meta:
        attack_type = "cve_2021_38147"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wipro Holmes Orchestrator 20.4.1 - Information Disclosure: Wipro Holmes Orchestrator 20.4.1 (20.4.1_02_11_2020) allows remote attackers to download arbitrary files, such as reports containing sensitive information, because authentication is not required for API access to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-38147"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38147, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-38147.yaml"
    strings:
        $path0 = /\/processexecution\/DownloadExcelFile\/Domain_Credential_Report_Excel(\/|;|$)/ nocase
        $path1 = /\/processexecution\/DownloadExcelFile\/Process_Report_Excel(\/|;|$)/ nocase
        $path2 = /\/processexecution\/DownloadExcelFile\/Infrastructure_Report_Excel(\/|;|$)/ nocase
        $path3 = /\/processexecution\/DownloadExcelFile\/Resolver_Report_Excel(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_38154_canon_devices {
    meta:
        attack_type = "cve_2021_38154"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Canon Devices - Authentication Bypass in Catwalk Server: Certain Canon devices manufactured in 2012 through 2020 (such as imageRUNNER ADVANCE iR-ADV C5250), when Catwalk Server is enabled for HTTP access, allow remote attackers to modify an e-mail address setting, and thus."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-38154"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38154, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-38154.yaml"
    strings:
        $path0 = /\/tryLogin\.cgi(\/|;|$)/ nocase
        $path1 = /\/checkLogin\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_38156_nagios_xi {
    meta:
        attack_type = "cve_2021_38156"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Nagios XI < 5.8.6 - Cross-Site Scripting: In Nagios XI before 5.8.6, XSS exists in the dashboard page (/dashboards/#) when administrative users attempt to edit a dashboard."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-38156"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38156, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-38156.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/nagiosxi\/ajaxhelper\.php(\/|;|$)/ nocase
        $path1 = /\/nagiosxi\/dashboards\/manage\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])cmd=updatedashboard(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_3831_gnuboard5 {
    meta:
        attack_type = "cve_2021_3831"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gnuboard 5 - Cross-Site Scripting: Gnuboard 5 contains a cross-site scripting vulnerability via the $_GET['LGD_OID'] parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-3831"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3831, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-3831.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mobile\/shop\/lg\/mispwapurl\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_38540_airflow {
    meta:
        attack_type = "cve_2021_38540"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Airflow - Unauthenticated Variable Import: Apache Airflow Airflow >=2.0.0 and <2.1.3 does not protect the variable import endpoint which allows unauthenticated users to hit that endpoint to add/modify Airflow variables used in DAGs, potentially resulting in a denial of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-38540"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38540, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-38540.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/variable\/varimport(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_38704_cliniccases {
    meta:
        attack_type = "cve_2021_38704"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ClinicCases 7.3.3 Cross-Site Scripting: ClinicCases 7.3.3 is susceptible to multiple reflected cross-site scripting vulnerabilities that could allow unauthenticated attackers to introduce arbitrary JavaScript by crafting a malicious URL. This can result in account takeover via."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-38704"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38704, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-38704.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/cliniccases\/lib\/php\/data\/messages_load\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_39211_glpi {
    meta:
        attack_type = "cve_2021_39211"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GLPI 9.2/<9.5.6 - Information Disclosure: GLPI 9.2 and prior to 9.5.6 is susceptible to information disclosure via the telemetry endpoint, which discloses GLPI and server information. An attacker can possibly obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39211"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39211, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39211.yaml"
    strings:
        $path0 = /\/ajax\/telemetry\.php(\/|;|$)/ nocase
        $path1 = /\/glpi\/ajax\/telemetry\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_39226_grafana {
    meta:
        attack_type = "cve_2021_39226"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Grafana Snapshot - Authentication Bypass: Grafana instances up to 7.5.11 and 8.1.5 allow remote unauthenticated users to view the snapshot associated with the lowest database key by accessing the literal paths /api/snapshot/:key or /dashboard/snapshot/:key. If the snapshot is."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39226"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39226, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39226.yaml"
    strings:
        $path0 = /\/api\/snapshots\/:key(\/|;|$)/ nocase
        $path1 = /\/dashboard\/snapshot\/:key(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_39312_true_ranker {
    meta:
        attack_type = "cve_2021_39312"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress True Ranker <2.2.4 - Local File Inclusion: WordPress True Ranker before version 2.2.4 allows sensitive configuration files such as wp-config.php, to be accessed via the src parameter found in the ~/admin/vendor/datatables/examples/resources/examples.php file via local."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39312"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39312, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39312.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/seo-local-rank\/admin\/vendor\/datatables\/examples\/resources\/examples\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])src=\/scripts\/simple\.php\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_39320_underconstruction {
    meta:
        attack_type = "cve_2021_39320"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Under Construction <1.19 - Cross-Site Scripting: WordPress Under Construction plugin before 1.19 contains a cross-site scripting vulnerability. The plugin echoes out the raw value of `$GLOBALS['PHP_SELF']` in the ucOptions.php file on certain configurations, including."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39320"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39320, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39320.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=under-construction(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_39327_bulletproof_security {
    meta:
        attack_type = "cve_2021_39327"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress BulletProof Security 5.1 Information Disclosure: The BulletProof Security WordPress plugin is vulnerable to sensitive information disclosure due to a file path disclosure in the publicly accessible ~/db_backup_log.txt file which grants attackers the full path of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39327"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39327, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39327.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/bulletproof-security\/admin\/htaccess\/db_backup_log\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_39341_optinmonster {
    meta:
        attack_type = "cve_2021_39341"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OptinMonster Plugin < 2.6.5 - Unprotected REST-API: The OptinMonster WordPress plugin is vulnerable to sensitive information disclosure and unauthorized setting updates due to insufficient authorization validation via the logged_in_or_has_api_key function in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39341"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39341, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39341.yaml"
    strings:
        $path0 = /\/wp-json\/omapp\/v1\/support(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_39411_hospital_management_system {
    meta:
        attack_type = "cve_2021_39411"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hospital Management System 1.0 - Cross-Site Scripting: Hospital Management System 1.0 contains a cross-site scripting vulnerability via the searchdata parameter in doctor/search.php and patient-search.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-39411"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39411, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-39411.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/hms\/doctor\/search\.php(\/|;|$)/ nocase
        $path1 = /\/hms\/admin\/patient-search\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40150_e1_zoom_firmware {
    meta:
        attack_type = "cve_2021_40150"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Reolink E1 Zoom Camera <=3.0.0.716 - Information Disclosure: Reolink E1 Zoom camera through 3.0.0.716 is susceptible to information disclosure. The web server discloses its configuration via the /conf/ directory that is mapped to a publicly accessible path. An attacker with."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40150.yaml"
    strings:
        $path0 = /\/conf\/nginx\.conf(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40272_monitor {
    meta:
        attack_type = "cve_2021_40272"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "IRTS OP5 Monitor - Cross-Site Scripting: OP5 Monitor 8.3.1, 8.3.2, and OP5 8.3.3 are vulnerable to Cross Site Scripting (XSS)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40272"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40272, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40272.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/help'onmouseover=alert\(document\.domain\)\/'\/;\/beta\/license(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40542_opensis {
    meta:
        attack_type = "cve_2021_40542"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Opensis-Classic 8.0 - Cross-Site Scripting: Opensis-Classic Version 8.0 is affected by cross-site scripting. An unauthenticated user can inject and execute JavaScript code through the link_url parameter in Ajax_url_encode.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40542"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40542, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40542.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Ajax_url_encode\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40661_ind780_firmware {
    meta:
        attack_type = "cve_2021_40661"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IND780 - Local File Inclusion: IND780 Advanced Weighing Terminals Build 8.0.07 March 19, 2018 (SS Label 'IND780_8.0.07'), Version 7.2.10 June 18, 2012 (SS Label 'IND780_7.2.10') is vulnerable to unauthenticated local file inclusion. It is possible to traverse the folders of the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40661"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40661, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40661.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/IND780\/excalweb\.dll(\/|;|$)/ nocase
        $param0 = /(^|[?&;])webpage=\.\.\/\.\.\/AutoCE\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_40859_compact_5500r_firmware {
    meta:
        attack_type = "cve_2021_40859"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Auerswald COMpact 5500R 7.8A and 8.0B Devices Backdoor: Auerswald COMpact 5500R 7.8A and 8.0B devices contain an unauthenticated endpoint ('https://192.168.1[.]2/about_state'), enabling the bad actor to gain backdoor access to a web interface that allows for resetting the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40859"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40859, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40859.yaml"
    strings:
        $path0 = /\/about_state(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40870_controller {
    meta:
        attack_type = "cve_2021_40870"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Aviatrix Controller 6.x before 6.5-1804.1922 - Remote Command Execution: Aviatrix Controller 6.x before 6.5-1804.1922 contains a vulnerability that allows unrestricted upload of a file with a dangerous type, which allows an unauthenticated user to execute arbitrary code via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40870"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40870, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40870.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/v1\/backend1(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=set_metric_gw_selections(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_40875_testrail {
    meta:
        attack_type = "cve_2021_40875"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gurock TestRail Application files.md5 Exposure: Improper access control in Gurock TestRail versions < 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40875.yaml"
    strings:
        $path0 = /\/testrail\/files\.md5(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_40960_galera_webtemplate {
    meta:
        attack_type = "cve_2021_40960"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Galera WebTemplate 1.0 Directory Traversal: Galera WebTemplate 1.0 is affected by a directory traversal vulnerability that could reveal information from /etc/passwd and /etc/shadow."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-40960"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40960, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40960.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/GallerySite/filesrc/fotoilan/388/middle/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41097_path {
    meta:
        attack_type = "cve_2021_41097"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Aurelia-Path < 1.1.7 - Prototype Pollution: Aurelia-path before 1.1.7 contains a prototype pollution caused by parsing malicious URL parameters, letting attackers modify Object.prototype, exploit requires the application to parse user-controlled URLs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41097"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41097, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41097.yaml"
    strings:
        $param0 = /(^|[?&;])__proto__\[polluted\]=polluted(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41174_grafana {
    meta:
        attack_type = "cve_2021_41174"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Grafana 8.0.0 <= v.8.2.2 - Angularjs Rendering Cross-Site Scripting: Grafana is an open-source platform for monitoring and observability. In affected versions if an attacker is able to convince a victim to visit a URL referencing a vulnerable page, arbitrary JavaScript content."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41174"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41174, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41174.yaml"
        response_type = "xss"
    strings:
        $path0 = "/dashboard/snapshot/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41192_redash {
    meta:
        attack_type = "cve_2021_41192"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Redash Setup Configuration - Default Secrets Disclosure: Redash Setup Configuration is vulnerable to default secrets disclosure (Insecure Default Initialization of Resource). If an admin sets up Redash versions <=10.0 and prior without explicitly specifying the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41192.yaml"
    strings:
        $path0 = /\/reset\/IjEi\.YhAmmQ\.cdQp7CnnVq02aQ05y8tSBddl-qs(\/|;|$)/ nocase
        $path1 = /\/redash\/reset\/IjEi\.YhAmmQ\.cdQp7CnnVq02aQ05y8tSBddl-qs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41266_minio_console {
    meta:
        attack_type = "cve_2021_41266"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MinIO Operator Console Authentication Bypass: MinIO Console is a graphical user interface for the for MinIO Operator. MinIO itself is a multi-cloud object storage project. Affected versions are subject to an authentication bypass issue in the Operator Console when an external."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41266"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41266, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41266.yaml"
    strings:
        $path0 = /\/api\/v1\/login\/oauth2\/auth(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41282_pfsense {
    meta:
        attack_type = "cve_2021_41282"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "pfSense - Arbitrary File Write: diag_routes.php in pfSense 2.5.2 allows sed data injection. Authenticated users are intended to be able to view data about the routes set in the firewall. The data is retrieved by executing the netstat utility, and then its output is parsed via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41282"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41282, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41282.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/diag_routes\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41291_ecs_router_controller_ecs_firm {
    meta:
        attack_type = "cve_2021_41291"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ECOA Building Automation System - Directory Traversal Content Disclosure: The ECOA BAS controller suffers from a directory traversal content disclosure vulnerability. Using the GET parameter cpath in File Manager (fmangersub), attackers can disclose directory content on the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41291"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41291, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41291.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])cpath=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41293_ecs_router_controller_ecs_firm {
    meta:
        attack_type = "cve_2021_41293"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ECOA Building Automation System - Arbitrary File Retrieval: The ECOA BAS controller suffers from an arbitrary file disclosure vulnerability. Using the 'fname' POST parameter in viewlog.jsp, attackers can disclose arbitrary files on the affected device and disclose sensitive and."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41293"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41293, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41293.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/viewlog\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fname=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41349_exchange_server {
    meta:
        attack_type = "cve_2021_41349"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microsoft Exchange Server Pre-Auth POST Based Cross-Site Scripting: Microsoft Exchange Server is vulnerable to a spoofing vulnerability. Be aware this CVE ID is unique from CVE-2021-42305."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41349"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41349, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41349.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/autodiscover\/autodiscover\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41381_micro_community {
    meta:
        attack_type = "cve_2021_41381"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Payara Micro Community 5.2021.6 Directory Traversal: Payara Micro Community 5.2021.6 and below contains a directory traversal vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41381"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41381, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41381.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/./WEB-INF/classes/META-INF/microprofile-config.properties" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41419_dvr_firmware {
    meta:
        attack_type = "cve_2021_41419"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "QVIS NVR/DVR - Remote Code Execution: QVIS NVR DVR before 2021-12-13 is vulnerable to Remote Code Execution via Java deserialization."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41419"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41419, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41419.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/qvisdvr/index.faces;jsessionid=" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41432_flatpress {
    meta:
        attack_type = "cve_2021_41432"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FlatPress 1.2.1 - Stored Cross-Site Scripting: FlatPress 1.2.1 contains a stored cross-site scripting vulnerability that allows for arbitrary execution of JavaScript commands through blog content. An attacker can possibly steal cookie-based authentication credentials and launch."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41432"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41432, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41432.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])subject=abcd(&|$)/ nocase
        $param1 = /(^|[?&;])save=Publish(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41460_ecshop {
    meta:
        attack_type = "cve_2021_41460"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ECShop 4.1.0 - SQL Injection: ECShop 4.1.0 has SQL injection vulnerability, which can be exploited by attackers to obtain sensitive information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41460"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41460, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41460.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/delete_cart_goods\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41467_justwriting {
    meta:
        attack_type = "cve_2021_41467"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JustWriting - Cross-Site Scripting: A cross-site scripting vulnerability in application/controllers/dropbox.php in JustWriting 1.0.0 and below allow remote attackers to inject arbitrary web script or HTML via the challenge parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41467.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/sync\/dropbox\/download(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41569_sas_intrnet {
    meta:
        attack_type = "cve_2021_41569"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SAS/Internet 9.4 1520 - Local File Inclusion: SAS/Internet 9.4 build 1520 and earlier allows local file inclusion. The samples library (included by default) in the appstart.sas file, allows end-users of the application to access the sample.webcsf1.sas program, which contains."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41569"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41569, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41569.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cgi-bin\/broker(\/|;|$)/ nocase
        $param0 = /(^|[?&;])csftyp=classic, ssfile1=\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])_SERVICE=targetservice(&|$)/ nocase
        $param2 = /(^|[?&;])_PROGRAM=sample\.webcsf1\.sas(&|$)/ nocase
        $param3 = /(^|[?&;])_ENTRY=SAMPLIB\.WEBSAMP\.PRINT_TO_HTML\.SOURCE(&|$)/ nocase
        $param4 = /(^|[?&;])DATASET=targetdataset(&|$)/ nocase
        $param5 = /(^|[?&;])TEMPFILE=Unknown(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41649_online_shopping_system_advance {
    meta:
        attack_type = "cve_2021_41649"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PuneethReddyHC Online Shopping System homeaction.php SQL Injection: An unauthenticated SQL injection vulnerability exists in PuneethReddyHC Online Shopping System through the /homeaction.php cat_id parameter. Using a post request does not sanitize the user input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41649"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41649, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41649.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/homeaction\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_41653_tl_wr840n_firmware {
    meta:
        attack_type = "cve_2021_41653"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TP-Link - OS Command Injection: The PING function on the TP-Link TL-WR840N EU v5 router with firmware through TL-WR840N(EU)_V5_171211 is vulnerable to remote code execution via a specially crafted payload in an IP address input field."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41653"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41653, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41653.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])X_TP_ConnName=ewan_ipoe_d(&|$)/ nocase
        $param1 = /(^|[?&;])diagnosticsState=Requested(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41691_opensis_student_information_sy {
    meta:
        attack_type = "cve_2021_41691"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "openSIS Student Information System 8.0 SQL Injection: openSIS Student Information System version 8.0 is susceptible to SQL injection via the student_id and TRANSFER[SCHOOL] parameters in POST request sent to /TransferredOutModal.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41691"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41691, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41691.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/TransferredOutModal\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])modfunc=detail(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_41951_resourcespace {
    meta:
        attack_type = "cve_2021_41951"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Resourcespace - Cross-Site Scripting: ResourceSpace before 9.6 rev 18290 is affected by a reflected cross-site scripting vulnerability in plugins/wordpress_sso/pages/index.php via the wordpress_user parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-41951"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41951, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41951.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugins\/wordpress_sso\/pages\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_42071_dvr_vx16_firmware {
    meta:
        attack_type = "cve_2021_42071"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Visual Tools DVR VX16 4.2.28.0 - Unauthenticated OS Command Injection: Visual Tools DVR VX16 4.2.28.0 could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42071"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42071, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42071.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/slogin\/login\.py(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_42237_experience_platform {
    meta:
        attack_type = "cve_2021_42237"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Sitecore Experience Platform Pre-Auth RCE: Sitecore XP 7.5 to Sitecore XP 8.2 Update 7 is vulnerable to an insecure deserialization attack where remote commands can be executed by an attacker with no authentication or special configuration required."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42237"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42237, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42237.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/sitecore\/shell\/ClientBin\/Reporting\/Report\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_42258_billquick_web_suite {
    meta:
        attack_type = "cve_2021_42258"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "BillQuick Web Suite SQL Injection: BQE BillQuick Web Suite 2018 through 2021 before 22.0.9.1 allows SQL injection for unauthenticated remote code execution. Successful exploitation can include the ability to execute arbitrary code as MSSQLSERVER$ via xp_cmdshell."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42258"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42258, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42258.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])__EVENTTARGET=cmdOK(&|$)/ nocase
        $param1 = /(^|[?&;])txtID=uname'(&|$)/ nocase
        $param2 = /(^|[?&;])txtPW=passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_42359_wp_dsgvo_tools {
    meta:
        attack_type = "cve_2021_42359"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP DSGVO Tools (GDPR) <= 3.1.23 - Unauthenticated Arbitrary Post Deletion: WP DSGVO Tools (GDPR) <= 3.1.23 had an AJAX action, admin-dismiss-unsubscribe, which lacked a capability check and a nonce check and was available to unauthenticated users, and did not check the post."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42359"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42359, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42359.yaml"
    strings:
        $param0 = /(^|[?&;])action=admin-dismiss-unsubscribe(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_42551_netbiblio {
    meta:
        attack_type = "cve_2021_42551"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NetBiblio WebOPAC - Cross-Site Scripting: NetBiblio WebOPAC before 4.0.0.320 is affected by a reflected cross-site scripting vulnerability in its Wikipedia module through /NetBiblio/search/shortview via the searchTerm parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42551"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42551, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42551.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/NetBiblio\/search\/shortview(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchType=Simple(&|$)/ nocase
        $param1 = /(^|[?&;])searchTerm=x'\+alert\(1\)\+'x(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_42567_central_authentication_service {
    meta:
        attack_type = "cve_2021_42567"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apereo CAS Cross-Site Scripting: Apereo CAS through 6.4.1 allows cross-site scripting via POST requests sent to the REST API endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42567"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42567, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42567.yaml"
        response_type = "xss"
    strings:
        $path0 = "/cas/v1/tickets/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_42663_online_event_booking_and_reser {
    meta:
        attack_type = "cve_2021_42663"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sourcecodester Online Event Booking and Reservation System 2.3.0 - Cross-Site Scripting: Sourcecodester Online Event Booking and Reservation System 2.3.0 contains a cross-site scripting vulnerability in PHP/MySQL via the msg parameter to /event-management/index.php. An attacker."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42663"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42663, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42663.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/views\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_42887_ex1200t_firmware {
    meta:
        attack_type = "cve_2021_42887"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TOTOLINK EX1200T 4.1.2cu.5215 - Authentication Bypass: TOTOLINK EX1200T 4.1.2cu.5215 is susceptible to authentication bypass. An attacker can bypass login by sending a specific request through formLoginAuth.htm, thus potentially being able to obtain sensitive information."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-42887"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-42887, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-42887.yaml"
    strings:
        $path0 = /\/formLoginAuth\.htm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_43287_gocd {
    meta:
        attack_type = "cve_2021_43287"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Pre-Auth Takeover of Build Pipelines in GoCD: GoCD contains a critical information disclosure vulnerability whose exploitation allows unauthenticated attackers to leak configuration information including build secrets and encryption keys."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-43287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-43287.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/go\/add-on\/business-continuity\/api\/plugin(\/|;|$)/ nocase
        $param0 = /(^|[?&;])pluginName=\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_43574_atmail {
    meta:
        attack_type = "cve_2021_43574"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atmail 6.5.0 - Cross-Site Scripting: Atmail 6.5.0 contains a cross-site scripting vulnerability in WebAdmin Control Pane via the format parameter to the default URI, which allows remote attackers to inject arbitrary web script or HTML via the format parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-43574"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43574, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-43574.yaml"
        response_type = "xss"
    strings:
        $path0 = "/atmail/webmail/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_43734_kkfileview {
    meta:
        attack_type = "cve_2021_43734"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "kkFileview v4.0.0 - Local File Inclusion: kkFileview v4.0.0 is vulnerable to local file inclusion which may lead to a sensitive file leak on a related host."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-43734"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43734, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-43734.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])urlPath=file:\/\/\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])urlPath=file:\/\/\/c:\/\/windows\/win\.ini(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_4374_wp_automatic {
    meta:
        attack_type = "cve_2021_4374"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Automatic Plugin - Unauthenticated Options Change: WordPress Automatic Plugin (versions 3.53.2 and below) contains a critical vulnerability that allows unauthenticated users to change arbitrary WordPress options through the process_form.php script. The vulnerable."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-4374"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-4374, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-4374.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-automatic\/process_form\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_43778_barcode {
    meta:
        attack_type = "cve_2021_43778"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GLPI plugin Barcode < 2.6.1 - Path Traversal Vulnerability.: Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-43778"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43778, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-43778.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/glpi\/plugins\/barcode\/front\/send\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_4380_pinterest_automatic_pin {
    meta:
        attack_type = "cve_2021_4380"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pinterest Automatic < 4.14.4 - Unauthenticated Arbitrary Options Update: The Pinterest Automatic plugin for WordPress is vulnerable to authorization bypass due to missing capability checks on the 'wp_pinterest_automatic_parse_request' function and the 'process_form.php' script."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-4380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-4380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-4380.yaml"
    strings:
        $param0 = /(^|[?&;])wp_pinterest_automatic=settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_43810_admidio {
    meta:
        attack_type = "cve_2021_43810"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Admidio - Cross-Site Scripting: A cross-site scripting vulnerability is present in Admidio prior to version 4.0.12. The reflected cross-site scripting vulnerability occurs because redirect.php does not properly validate the value of the url parameter. Through this."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-43810"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43810, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-43810.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/adm_program\/system\/redirect\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44077_manageengine_servicedesk_plus {
    meta:
        attack_type = "cve_2021_44077"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zoho ManageEngine ServiceDesk Plus - Remote Code Execution: Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44077"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44077, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44077.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/RestAPI\/ImportTechnicians(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44138_resin {
    meta:
        attack_type = "cve_2021_44138"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Caucho Resin >=4.0.52 <=4.0.56 - Directory traversal: There is a Directory traversal vulnerability in Caucho Resin, as distributed in Resin 4.0.52 - 4.0.56, which allows remote attackers to read files in arbitrary directories via a ; in a pathname within an HTTP request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44138.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/resin-doc\/;\/WEB-INF\/resin-web\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44139_sentinel {
    meta:
        attack_type = "cve_2021_44139"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Alibaba Sentinel - Server-side request forgery (SSRF): There is a Pre-Auth SSRF vulnerability in Alibaba Sentinel version 1.8.2, which allows remote unauthenticated attackers to perform SSRF attacks via the /registry/machine endpoint through the ip parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44139"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44139, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44139.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/registry\/machine(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44152_reprise_license_manager {
    meta:
        attack_type = "cve_2021_44152"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Reprise License Manager 14.2 - Authentication Bypass: Reprise License Manager (RLM) 14.2 does not verify authentication or authorization and allows unauthenticated users to change the password of any existing user."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44152"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44152, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44152.yaml"
    strings:
        $path0 = /\/goforms\/menu(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_4448_kaswara {
    meta:
        attack_type = "cve_2021_4448"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kaswara Modern VC Addons <= 3.0.1 - Missing Authorization: The Kaswara Modern VC Addons plugin for WordPress is vulnerable to authorization bypass in versions up to, and including, 3.0.1 due to insufficient capability checking on various AJAX actions. This makes it possible for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-4448"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-4448, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-4448.yaml"
    strings:
        $param0 = /(^|[?&;])action=kaswaraImportDemo(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_4449_zoomsounds {
    meta:
        attack_type = "cve_2021_4449"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZoomSounds Plugin - Unauthenticated Arbitrary File Upload: ZoomSounds plugin for WordPress contains a file upload vulnerability in savepng.php"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-4449"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-4449, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-4449.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/dzs-zoomsounds\/savepng\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44515_manageengine_desktop_central {
    meta:
        attack_type = "cve_2021_44515"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zoho ManageEngine Desktop Central - Remote Code Execution: Zoho ManageEngine Desktop Central contains an authentication bypass vulnerability that could allow an attacker to execute arbitrary code in the Desktop Central MSP server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44515"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44515, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44515.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/STATE_ID\/123\/agentLogUploader(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44529_endpoint_manager_cloud_service {
    meta:
        attack_type = "cve_2021_44529"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti EPM Cloud Services Appliance Code Injection: Ivanti EPM Cloud Services Appliance (CSA) before version 4.6.0-512 is susceptible to a code injection vulnerability because it allows an unauthenticated user to execute arbitrary code with limited permissions (nobody)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44529"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44529, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44529.yaml"
    strings:
        $path0 = /\/client\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_44848_thinfinity_virtualui {
    meta:
        attack_type = "cve_2021_44848"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Thinfinity VirtualUI User Enumeration: Thinfinity VirtualUI (before v3.0), /changePassword returns different responses for requests depending on whether the username exists. It may enumerate OS users (Administrator, Guest, etc.)"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-44848"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44848, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44848.yaml"
    strings:
        $path0 = /\/changePassword(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45027_oliver_5_library_server_8_00_0 {
    meta:
        attack_type = "cve_2021_45027"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oliver 5 Library Server <8.00.008.053 - Local File Inclusion: Oliver 5 Library Server versions prior to 8.00.008.053 are vulnerable to local file inclusion via the FileServlet function."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45027"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45027, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45027.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/oliver\/FileServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])source=serverFile(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_45043_hd_network_real_time_monitorin {
    meta:
        attack_type = "cve_2021_45043"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HD-Network Realtime Monitoring System 2.0 - Local File Inclusion: Instances of HD-Network Realtime Monitoring System version 2.0 are vulnerable to a Local File Inclusion vulnerability which allows remote unauthenticated attackers to view confidential information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45043"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45043, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45043.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/language\/lang(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45232_apisix_dashboard {
    meta:
        attack_type = "cve_2021_45232"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache APISIX Dashboard <2.10.1 - API Unauthorized Access: In Apache APISIX Dashboard before 2.10.1, the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin.' While all APIs and authentication middleware are developed based on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45232"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45232, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45232.yaml"
    strings:
        $path0 = /\/apisix\/admin\/migrate\/export(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45380_appcms {
    meta:
        attack_type = "cve_2021_45380"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AppCMS - Cross-Site Scripting: AppCMS 2.0.101 has a cross-site scripting vulnerability in /templates/m/inc_head.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45380.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/templates\/m\/inc_head\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45382_dir_820l_firmware {
    meta:
        attack_type = "cve_2021_45382"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "D-Link - Remote Command Execution: A Remote Command Execution (RCE) vulnerability exists in all series H/W revisions D-link DIR-810L, DIR-820L/LW, DIR-826L, DIR-830L, and DIR-836L routers via the DDNS function in ncc2 binary file"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45382"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45382, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45382.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ddns_check\.ccp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ccp_act=doCheck(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_45420_dixell_xweb_500 {
    meta:
        attack_type = "cve_2021_45420"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Emerson Dixell XWEB-500 - Arbitrary File Write: Emerson Dixell XWEB-500 contains an arbitrary file write caused by unauthenticated access to /cgi-bin/logo_extra_upload.cgi, /cgi-bin/cal_save.cgi, and /cgi-bin/lo_utils.cgi, letting attackers write any file on the system, exploit."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45420"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45420, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45420.yaml"
    strings:
        $path0 = /\/cgi-bin\/logo_extra_upload\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45422_reprise_license_manager {
    meta:
        attack_type = "cve_2021_45422"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Reprise License Manager 14.2 - Cross-Site Scripting: Reprise License Manager 14.2 contains a cross-site scripting vulnerability in the /goform/activate_process 'count' parameter via GET."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45422"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45422, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45422.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/goform\/activate_process(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45793_senayan_library_management_sys {
    meta:
        attack_type = "cve_2021_45793"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Slims9 Bulian 9.4.2 - SQL Injection: Slims9 Bulian 9.4.2 is affected by SQL injection in lib/comment.inc.php. User data can be obtained."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45793"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45793, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45793.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])SaveComment=Save comment(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_45811_osticket {
    meta:
        attack_type = "cve_2021_45811"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "osTicket 1.15.x - SQL Injection: A SQL injection vulnerability in the 'Search' functionality of 'tickets.php' page in osTicket 1.15.x allows authenticated attackers to execute arbitrary SQL commands via the 'keywords' and 'topic_id' URL parameters combination."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45811"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45811, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45811.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])topic_id=topic_id_val(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_45967_cloud_phone_system {
    meta:
        attack_type = "cve_2021_45967"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pascom CPS Server-Side Request Forgery: Pascom versions before 7.20 packaged with Cloud Phone System contain a known server-side request forgery vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45967"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45967, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45967.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/services\/pluginscript\/\.\.;\/\.\.;\/\.\.;\/getFavicon(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_45968_jive {
    meta:
        attack_type = "cve_2021_45968"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Pascom CPS - Local File Inclusion: Pascom packaged with Cloud Phone System (CPS) versions before 7.20 contain a known local file inclusion vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-45968"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-45968, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-45968.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/services/pluginscript/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46005_car_rental_management_system {
    meta:
        attack_type = "cve_2021_46005"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sourcecodester Car Rental Management System 1.0 - Stored Cross-Site Scripting: Sourcecodester Car Rental Management System 1.0 is vulnerable to cross-site scripting via the vehicalorcview parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46005"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46005, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46005.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/post-avehical\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46068_vehicle_service_management_sys {
    meta:
        attack_type = "cve_2021_46068"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vehicle Service Management System - Stored Cross-Site Scripting: A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the My Account Section in login panel."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46068"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46068, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46068.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/classes\/Users\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46069_vehicle_service_management_sys {
    meta:
        attack_type = "cve_2021_46069"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vehicle Service Management System 1.0 - Stored Cross Site Scripting: Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Mechanic List section in login panel."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46069"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46069, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46069.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])f=save_mechanic(&|$)/ nocase
        $param1 = /(^|[?&;])email=asd1@asd\.com(&|$)/ nocase
        $param2 = /(^|[?&;])page=mechanics(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_46071_vehicle_service_management_sys {
    meta:
        attack_type = "cve_2021_46071"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ehicle Service Management System 1.0 - Cross-Site Scripting: Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Category List section in login panel."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46071"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46071, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46071.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])f=save_category(&|$)/ nocase
        $param1 = /(^|[?&;])page=maintenance\/category(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_46072_vehicle_service_management_sys {
    meta:
        attack_type = "cve_2021_46072"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vehicle Service Management System 1.0 - Stored Cross Site Scripting: Vehicle Service Management System 1.0 contains a stored cross-site scripting vulnerability via the Service List section in login panel."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46072"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46072, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46072.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=maintenance\/services(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2021_46073_vehicle_service_management_sys {
    meta:
        attack_type = "cve_2021_46073"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vehicle Service Management System 1.0 - Cross Site Scripting: Vehicle Service Management System 1.0 contains a cross-site scripting vulnerability via the User List section in login panel."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46073"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46073, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46073.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/vehicle_service\/classes\/Login\.php(\/|;|$)/ nocase
        $path1 = /\/vehicle_service\/classes\/Users\.php(\/|;|$)/ nocase
        $path2 = "/vehicle_service/admin/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46104_webp_server_go {
    meta:
        attack_type = "cve_2021_46104"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "webp_server_go 0.4.0 - Path Traversal: webp_server_go 0.4.0 contains a path traversal caused by insufficient sanitization in file handling, letting attackers read arbitrary files on the server, exploit requires attacker to send crafted requests."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46104"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46104, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46104.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46107_ligeo_basics {
    meta:
        attack_type = "cve_2021_46107"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ligeo Archives Ligeo Basics - Server Side Request Forgery: Ligeo Archives Ligeo Basics as of 02_01-2022 is vulnerable to Server Side Request Forgery (SSRF) which allows an attacker to read any documents via the download features."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46107, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46107.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/archive\/download(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46379_dir_850l_firmware {
    meta:
        attack_type = "cve_2021_46379"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "D-Link DIR850 ET850-1.08TRb03 - Open Redirect: DLink DIR850 ET850-1.08TRb03 contains incorrect access control vulnerability in URL redirection, which can be used to mislead users to go to untrusted sites."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46379"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46379, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46379.yaml"
    strings:
        $path0 = /\/boafrm\/formWlanRedirect(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46381_dap_1620 {
    meta:
        attack_type = "cve_2021_46381"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "D-Link DAP-1620 - Local File Inclusion: D-Link DAP-1620 is susceptible to local file Inclusion due to path traversal that can lead to unauthorized internal files reading [/etc/passwd] and [/etc/shadow]."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46381"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46381, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46381.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/apply\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46387_zywall_2_plus_internet_securit {
    meta:
        attack_type = "cve_2021_46387"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zyxel ZyWALL 2 Plus Internet Security Appliance - Cross-Site Scripting: ZyXEL ZyWALL 2 Plus Internet Security Appliance contains a cross-site scripting vulnerability. Insecure URI handling leads to bypass of security restrictions, which allows an attacker to execute arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46387"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46387, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46387.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Forms\/rpAuth_1(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_46417_colibri_firmware {
    meta:
        attack_type = "cve_2021_46417"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local File Inclusion: Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 is susceptible to local file inclusion because of insecure handling of a download function that leads to disclosure of internal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-46417"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-46417, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-46417.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cgi-bin\/tsaupload\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2021_47795_geowebserver {
    meta:
        attack_type = "cve_2021_47795"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GeoVision GeoWebServer <= 5.3.3 - Local File Inclusion / Cross-Site Scripting: GeoVision GeoWebServer 5.3.3 and prior is vulnerable to local file inclusion and cross-site scripting due to improper sanitization of user-supplied input in the WebStrings.srf endpoint. An."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2021-47795"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-47795, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-47795.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/Visitor\/bin\/WebStrings\.srf(\/|;|$)/ nocase
        $param0 = /(^|[?&;])obj_name=win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
