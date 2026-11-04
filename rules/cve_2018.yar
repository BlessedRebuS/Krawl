// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2018_0127_rv132w_firmware {
    meta:
        attack_type = "cve_2018_0127"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco RV132W/RV134W Router - Information Disclosure: Cisco RV132W ADSL2+ Wireless-N VPN Routers and Cisco RV134W VDSL2 Wireless-AC VPN Routers could allow an unauthenticated, remote attacker to view configuration parameters for an affected device via the web interface, which."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-0127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-0127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-0127.yaml"
    strings:
        $path0 = /\/dumpmdm\.cmd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_0296_adaptive_security_appliance_so {
    meta:
        attack_type = "cve_2018_0296"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Cisco ASA - Local File Inclusion: Cisco Adaptive Security Appliances (ASA) web interfaces could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-0296"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-0296, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-0296.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/\+CSCOU\+\/\.\.\/\+CSCOE\+\/files\/file_list\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_1000130_webarchive_agent {
    meta:
        attack_type = "cve_2018_1000130"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jolokia Agent - JNDI Code Injection: Jolokia agent is vulnerable to a JNDI injection vulnerability that allows a remote attacker to run arbitrary Java code on the server when the agent is in proxy mode."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1000130"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000130, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1000130.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/jolokia\/read\/getDiagnosticOptions(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_1000600_github {
    meta:
        attack_type = "cve_2018_1000600"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jenkins GitHub Plugin <=1.29.1 - Server-Side Request Forgery: Jenkins GitHub Plugin 1.29.1 and earlier is susceptible to server-side request forgery via GitHubTokenCredentialsCreator.java, which allows attackers to leverage attacker-specified credentials IDs obtained through."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1000600"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000600, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1000600.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/securityRealm\/user\/admin\/descriptorByName\/org\.jenkinsci\.plugins\.github\.config\.GitHubTokenCredentialsCreator\/createTokenByPassword(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_1000856_domainmod {
    meta:
        attack_type = "cve_2018_1000856"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 is vulnerable to cross-site scripting via the segments/add.php Segment Name field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1000856"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000856, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1000856.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/segments\/add\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])raw_domain_list=test\.com(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_10093_420hd_ip_phone_firmware {
    meta:
        attack_type = "cve_2018_10093"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AudioCodes 420HD - Remote Code Execution: AudioCodes IP phone 420HD devices using firmware version 2.2.12.126 allow remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10093"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10093, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10093.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/command\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_10095_dolibarr {
    meta:
        attack_type = "cve_2018_10095"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Dolibarr <7.0.2 - Cross-Site Scripting: Dolibarr before 7.0.2 is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the foruserlogin parameter to adherents/cartes/carte.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10095"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10095, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10095.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/dolibarr\/adherents\/cartes\/carte\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mode=cardlogin(&|$)/ nocase
        $param1 = /(^|[?&;])optioncss=print(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_10245_awstats_7_5 {
    meta:
        attack_type = "cve_2018_10245"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AWStats <= 7.5 - Full Path Disclosure: AWStats 7.6 contains a full path disclosure caused by improper handling of framename and update parameters in awstats.pl, letting remote attackers determine server file paths, exploit requires sending crafted parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10245"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10245, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10245.yaml"
    strings:
        $path0 = /\/cgi-bin\/awstats\.pl(\/|;|$)/ nocase
        $path1 = /\/awstats\/awstats\.pl(\/|;|$)/ nocase
        $path2 = /\/awstats\.pl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_10735_nagios_xi {
    meta:
        attack_type = "cve_2018_10735"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NagiosXI <= 5.4.12 `commandline.php` SQL injection: A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/commandline.php cname parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10735"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10735, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10735.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/nagiosql\/admin\/commandline\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_10736_nagios_xi {
    meta:
        attack_type = "cve_2018_10736"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NagiosXI <= 5.4.12 - SQL injection: A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/info.php key1 parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10736"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10736, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10736.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/nagiosql\/admin\/info\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_10737_nagios_xi {
    meta:
        attack_type = "cve_2018_10737"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NagiosXI <= 5.4.12 logbook.php SQL injection: A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/logbook.php txtSearch parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10737"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10737, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10737.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/nagiosql\/admin\/logbook\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_10738_nagios_xi {
    meta:
        attack_type = "cve_2018_10738"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NagiosXI <= 5.4.12 menuaccess.php - SQL injection: A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/menuaccess.php chbKey1 parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-10738"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10738, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-10738.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/nagiosql\/admin\/menuaccess\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_11133_kace_system_management_applian {
    meta:
        attack_type = "cve_2018_11133"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Quest KACE SMA /common/run_cross_report.php 'fmt' XSS: The 'fmt' parameter of the '/common/run_cross_report.php' script in the the Quest KACE System Management Appliance 8.0.318 is vulnerable to cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11133.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/common\/run_cross_report\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fmt=xls34403'\);alert\(document\.domain\)\/\/952(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_11231_divido {
    meta:
        attack_type = "cve_2018_11231"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Opencart Divido - Sql Injection: OpenCart Divido plugin is susceptible to SQL injection"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11231"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11231, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11231.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])route=extension\/payment\/divido\/update(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_11409_splunk {
    meta:
        attack_type = "cve_2018_11409"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Splunk <=7.0.1 - Information Disclosure: Splunk through 7.0.1 is susceptible to information disclosure by appending __raw/services/server/info/server-info?output_mode=json to a query, as demonstrated by discovering a license key."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11409"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11409, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11409.yaml"
    strings:
        $path0 = /\/en-US\/splunkd\/__raw\/services\/server\/info\/server-info(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_11473_monstra {
    meta:
        attack_type = "cve_2018_11473"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Monstra CMS 3.0.4 - Cross-Site Scripting: Monstra CMS 3.0.4 contains a cross-site scripting vulnerability via the registration form (i.e., the login parameter to users/registration). An attacker can inject arbitrary script in the browser of an unsuspecting user in the context."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11473"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11473, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11473.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/users\/registration(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_11511_asustor_data_master {
    meta:
        attack_type = "cve_2018_11511"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ASUSTOR ADM 3.1.0.RFQ3 - SQL Injection: ASUSTOR ADM version 3.1.0.RFQ3 is vulnerable to SQL injection via the album_id parameter in the /photo-gallery/api/album/tree_lists/ endpoint. An attacker can exploit this vulnerability to execute arbitrary SQL commands on the database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11511"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11511, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11511.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])album_id=106298411 AND SLEEP\(9\)(&|$)/ nocase
        $param1 = /(^|[?&;])scope=106298414 AND SLEEP\(9\)(&|$)/ nocase
        $param2 = /(^|[?&;])api_mode=browse(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_11686_flowpaper {
    meta:
        attack_type = "cve_2018_11686"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FlexPaper/FlowPaper 2.3.6 - Remote Code Execution: The Publish Service in FlexPaper (later renamed FlowPaper) 2.3.6 allows remote code execution via setup.php and change_config.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11686"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11686, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11686.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/php\/change_config\.php(\/|;|$)/ nocase
        $path1 = /\/php\/config\/output\.txt(\/|;|$)/ nocase
        $param0 = /(^|[?&;])SWF_Directory=config\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_11709_wpforo_forum {
    meta:
        attack_type = "cve_2018_11709"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress wpForo Forum <= 1.4.11 - Cross-Site Scripting: WordPress wpForo Forum plugin before 1.4.12 for WordPress allows unauthenticated reflected cross-site scripting via the URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-11709"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11709, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-11709.yaml"
        response_type = "xss"
    strings:
        $path0 = "/index.php/community/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_12031_intelligent_power_manager {
    meta:
        attack_type = "cve_2018_12031"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Eaton Intelligent Power Manager 1.6 - Directory Traversal: Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via directory traversal, which can lead to sensitive information disclosure, denial of service and code execution."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-12031"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-12031, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-12031.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=downloadFirmware(&|$)/ nocase
        $param1 = /(^|[?&;])firmware=\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param2 = /(^|[?&;])firmware=\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Windows\/win\.ini(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_1207_emc_idrac7 {
    meta:
        attack_type = "cve_2018_1207"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dell iDRAC7/8 Devices - Remote Code Injection: Dell EMC iDRAC7/iDRAC8, versions prior to 2.52.52.52, contain a CGI injection vulnerability which could be used to execute remote code. A remote unauthenticated attacker may potentially be able to use CGI variables to execute."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1207, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1207.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])LD_DEBUG=files(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_1217_emc_avamar_emc_integrated_data {
    meta:
        attack_type = "cve_2018_1217"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dell EMC Avamar and Integrated Data Protection Appliance Installation Manager - Invalid Access Control: Avamar Installation Manager in Dell EMC Avamar Server 7.3.1, 7.4.1, and 7.5.0, and Dell EMC Integrated Data Protection Appliance 2.0 and 2.1, is affected by a missing access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1217"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1217, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1217.yaml"
    strings:
        $path0 = /\/avi\/avigui\/avigwt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_12296_nas_os {
    meta:
        attack_type = "cve_2018_12296"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Seagate NAS OS 4.3.15.1 - Server Information Disclosure: Seagate NAS OS version 4.3.15.1 has insufficient access control which allows attackers to obtain information about the NAS without authentication via empty POST requests in /api/external/7.0/system.System.get_infos."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-12296"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-12296, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-12296.yaml"
    strings:
        $path0 = /\/api\/external\/7\.0\/system\.System\.get_infos(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_12675_h_264_poe_ip_camera_firmware {
    meta:
        attack_type = "cve_2018_12675"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SV3C HD Camera L Series - Open Redirect: SV3C HD Camera L Series 2.3.4.2103-S50-NTD-B20170508B and 2.3.4.2103-S50-NTD-B20170823B contains an open redirect vulnerability. It does not perform origin checks on URLs in the camera's web interface, which can be leveraged to send a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-12675"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-12675, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-12675.yaml"
    strings:
        $path0 = /\/web\/cgi-bin\/hi3510\/param\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])cmd=setmobilesnapattr(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_1271_spring_framework {
    meta:
        attack_type = "cve_2018_1271"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Spring MVC Framework - Local File Inclusion: Spring MVC Framework versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported are vulnerable to local file inclusion because they allow applications to configure Spring MVC to serve static resources (e.g.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-1271"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1271, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-1271.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/static\/%5c%5c\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/windows\/win\.ini(\/|;|$)/ nocase
        $path1 = /\/spring-mvc-showcase\/resources\/%5c%5c\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/\.\.%5c\/windows\/win\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_12909_webgrind {
    meta:
        attack_type = "cve_2018_12909"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Webgrind <= 1.5 - Local File Inclusion: Webgrind 1.5 relies on user input to display a file, which lets anyone view files from the local filesystem (that the webserver user has access to) via an index.php?op=fileviewer&file= URI"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-12909"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-12909, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-12909.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])op=fileviewer(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_12998_firewall_analyzer {
    meta:
        attack_type = "cve_2018_12998"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zoho manageengine - Cross-Site Scripting: Zoho manageengine is vulnerable to reflected cross-site scripting. This impacts Zoho ManageEngine Netflow Analyzer before build 123137, Network Configuration Manager before build 123128, OpManager before build 123148, OpUtils before."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-12998"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-12998, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-12998.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/servlet\/com\.adventnet\.me\.opmanager\.servlet\.FailOverHelperServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_13380_fortios {
    meta:
        attack_type = "cve_2018_13380"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Fortinet FortiOS - Cross-Site Scripting: Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.7, 5.4.0 to 5.4.12, 5.2 and below versions under SSL VPN web portal are vulnerable to cross-site scripting and allows attacker to execute unauthorized malicious script code via the error or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-13380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-13380.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/remote\/error(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_13980_zeta_producer {
    meta:
        attack_type = "cve_2018_13980"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zeta Producer Desktop CMS <14.2.1 - Local File Inclusion: Zeta Producer Desktop CMS before 14.2.1 is vulnerable to local file inclusion if the plugin 'filebrowser' is installed because of assets/php/filebrowser/filebrowser.main.php?file=../ directory traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-13980"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13980, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-13980.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/assets\/php\/filebrowser\/filebrowser\.main\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_14013_zimbra_collaboration_suite {
    meta:
        attack_type = "cve_2018_14013"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Synacor Zimbra Collaboration Suite Collaboration <8.8.11 - Cross-Site Scripting: Synacor Zimbra Collaboration Suite Collaboration before 8.8.11 is vulnerable to cross-site scripting via the AJAX and html web clients."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-14013"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14013, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-14013.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/zimbra\/h\/search(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_14728_responsive_filemanager {
    meta:
        attack_type = "cve_2018_14728"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Responsive filemanager 9.13.1 Server-Side Request Forgery: Responsive filemanager 9.13.1 is susceptible to server-side request forgery in upload.php via the url parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-14728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-14728.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/filemanager\/upload\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_14912_cgit {
    meta:
        attack_type = "cve_2018_14912"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "cgit < 1.2.1 - Directory Traversal: cGit < 1.2.1 via cgit_clone_objects has a directory traversal vulnerability when `enable-http-clone=1` is not turned off, as demonstrated by a cgit/cgit.cgi/git/objects/?path=../ request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-14912"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14912, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-14912.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgit/cgit.cgi/git/objects/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_14931_intellect_core_banking {
    meta:
        attack_type = "cve_2018_14931"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Polarisft Intellect Core Banking Software Version 9.7.1 - Open Redirect: Polarisft Intellect Core Banking Software Version 9.7.1 is susceptible to an open redirect issue in the Core and Portal modules via the /IntellectMain.jsp?IntellectSystem= URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-14931"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14931, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-14931.yaml"
    strings:
        $path0 = /\/IntellectMain\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_14933_nvrmini_firmware {
    meta:
        attack_type = "cve_2018_14933"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "NUUO NVRmini - Remote Command Execution: NUUO NVRmini is vulnerable to unauthenticated remote command execution through the upgrade_handle.php file. The vulnerability allows an attacker to execute arbitrary commands by manipulating the uploaddir parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-14933"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14933, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-14933.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/upgrade_handle\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])cmd=writeuploaddir(&|$)/ nocase
        $param1 = /(^|[?&;])uploaddir=';id;'(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_15138_ipecs_nms {
    meta:
        attack_type = "cve_2018_15138"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LG-Ericsson iPECS NMS 30M - Local File Inclusion: Ericsson-LG iPECS NMS 30M allows local file inclusion via ipecs-cm/download?filename=../ URIs."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15138.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ipecs-cm\/download(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_15517_central_wifimanager {
    meta:
        attack_type = "cve_2018_15517"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "D-Link Central WifiManager - Server-Side Request Forgery: D-Link Central WifiManager is susceptible to server-side request forgery. The MailConnect feature on D-Link Central WiFiManager CWM-100 1.03 r0098 devices is intended to check a connection to an SMTP server but actually."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15517"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15517, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15517.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/index.php/System/MailConnect/host/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_15535_responsive_filemanager {
    meta:
        attack_type = "cve_2018_15535"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Responsive FileManager <9.13.4 - Local File Inclusion: Responsive FileManager before version 9.13.4 is vulnerable to local file inclusion via filemanager/ajax_calls.php because it uses external input to construct a pathname that should be within a restricted directory, aka."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15535"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15535, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15535.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/filemanager\/ajax_calls\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sub_action=preview(&|$)/ nocase
        $param1 = /(^|[?&;])title=source(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_15745_dvr {
    meta:
        attack_type = "cve_2018_15745"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Argus Surveillance DVR 4.0.0.0 - Local File Inclusion: Argus Surveillance DVR 4.0.0.0 devices allow unauthenticated local file inclusion, leading to file disclosure via a ..%2F in the WEBACCOUNT.CGI RESULTPAGE parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15745"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15745, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15745.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/WEBACCOUNT\.CGI(\/|;|$)/ nocase
        $param0 = /(^|[?&;])RESULTPAGE=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Windows\/system\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_15917_jorani {
    meta:
        attack_type = "cve_2018_15917"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jorani Leave Management System 0.6.5 - Cross-Site Scripting: Persistent cross-site scripting (XSS) issues in Jorani 0.6.5 allow remote attackers to inject arbitrary web script or HTML via the language parameter to session/language."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15917.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/session\/language(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_15961_coldfusion {
    meta:
        attack_type = "cve_2018_15961"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe ColdFusion - Unrestricted File Upload Remote Code Execution: Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-15961"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15961, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-15961.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cf_scripts\/scripts\/ajax\/ckeditor\/plugins\/filemanager\/upload\.cfm(\/|;|$)/ nocase
        $path1 = "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16059_wirelesshart_fieldgate_swg70_f {
    meta:
        attack_type = "cve_2018_16059"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WirelessHART Fieldgate SWG70 3.0 - Local File Inclusion: WirelessHART Fieldgate SWG70 3.0 is vulnerable to local file inclusion via the fcgi-bin/wgsetcgi filename parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16059.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/fcgi-bin\/wgsetcgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])origin=cw\.Communication\.File\.Read(&|$)/ nocase
        $param1 = /(^|[?&;])transaction=fileCommand(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_16139_bibliopac {
    meta:
        attack_type = "cve_2018_16139"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "BIBLIOsoft BIBLIOpac 2008 - Cross-Site Scripting: BIBLIOsoft BIBLIOpac 2008 contains a cross-site scripting vulnerability via the db or action parameter to bin/wxis.exe/bibliopac/, which allows a remote attacker to inject arbitrary web script or HTML."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16139"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16139, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16139.yaml"
        response_type = "xss"
    strings:
        $path0 = "/bibliopac/bin/wxis.exe/bibliopac/" ascii nocase
        $param0 = /(^|[?&;])IsisScript=bibliopac\/bin\/bibliopac\.xic(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_16159_gift_vouchers {
    meta:
        attack_type = "cve_2018_16159"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Gift Voucher <4.1.8 - Blind SQL Injection: WordPress Gift Vouchers plugin before 4.1.8 contains a blind SQL injection vulnerability via the template_id parameter in a wp-admin/admin-ajax.php wpgv_doajax_front_template request. An attacker can possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16159.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=wpgv_doajax_front_template(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_16283_wechat_brodcast {
    meta:
        attack_type = "cve_2018_16283"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Plugin Wechat Broadcast 1.2.0 - Local File Inclusion: WordPress Wechat Broadcast plugin 1.2.0 and earlier allows Directory Traversal via the Image.php url parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16283"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16283, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16283.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wechat-broadcast\/wechat\/Image\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16288_supersign_cms {
    meta:
        attack_type = "cve_2018_16288"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LG SuperSign EZ CMS 2.5 - Local File Inclusion: LG SuperSign CMS 2.5 allows reading of arbitrary files via signEzUI/playlist/edit/upload/..%2f URIs - aka local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16288"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16288, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16288.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/signEzUI\/playlist\/edit\/upload\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16299_localize_my_post {
    meta:
        attack_type = "cve_2018_16299"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Localize My Post 1.0 - Local File Inclusion: WordPress Localize My Post 1.0 is susceptible to local file inclusion via the ajax/include.php file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16299"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16299, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16299.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/localize-my-post\/ajax\/include\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16668_circarlife_scada {
    meta:
        attack_type = "cve_2018_16668"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CirCarLife <4.3 - Improper Authentication: CirCarLife before 4.3 is susceptible to improper authentication. An internal installation path disclosure exists due to the lack of authentication for /html/repository.System. An attacker can obtain sensitive information, modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16668"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16668, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16668.yaml"
    strings:
        $path0 = /\/html\/repository(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16670_circarlife_scada {
    meta:
        attack_type = "cve_2018_16670"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CirCarLife <4.3 - Improper Authentication: CirCarLife before 4.3 is susceptible to improper authentication. A PLC status disclosure exists due to lack of authentication for /html/devstat.html. An attacker can obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16670"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16670, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16670.yaml"
    strings:
        $path0 = /\/services\/user\/values\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16671_circarlife_scada {
    meta:
        attack_type = "cve_2018_16671"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CirCarLife <4.3 - Improper Authentication: CirCarLife before 4.3 is susceptible to improper authentication. A system software information disclosure exists due to lack of authentication for /html/device-id. An attacker can obtain sensitive information, modify data, and/or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16671"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16671, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16671.yaml"
    strings:
        $path0 = /\/html\/device-id(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16716_ncbi_toolbox {
    meta:
        attack_type = "cve_2018_16716"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NCBI ToolBox - Directory Traversal: NCBI ToolBox 2.0.7 through 2.2.26 legacy versions contain a path traversal vulnerability via viewcgi.cgi which may result in reading of arbitrary files (i.e., significant information disclosure) or file deletion via the nph-viewgif.cgi query."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16716"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16716, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16716.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/blast\/nph-viewgif\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16761_eventum {
    meta:
        attack_type = "cve_2018_16761"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Eventum <3.4.0 - Open Redirect: Eventum before 3.4.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16761"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16761, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16761.yaml"
    strings:
        $path0 = /\/select_project\.php(\/|;|$)/ nocase
        $path1 = /\/clock_status\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_16979_monstra {
    meta:
        attack_type = "cve_2018_16979"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Monstra CMS 3.0.4 - HTTP Header Injection: Monstra CMS 3.0.4 is susceptible to HTTP header injection in the plugins/captcha/crypt/cryptographp.php cfg parameter. An attacker can potentially supply invalid input and cause the server to allow redirects to attacker-controlled."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-16979"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-16979, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-16979.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugins\/captcha\/crypt\/cryptographp\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_17153_my_cloud_wdbctl0020hwt_firmwar {
    meta:
        attack_type = "cve_2018_17153"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Western Digital MyCloud NAS - Authentication Bypass: It was discovered that the Western Digital My Cloud device before 2.30.196 is affected by an authentication bypass vulnerability. An unauthenticated attacker can exploit this vulnerability to authenticate as an admin user."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17153.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/web\/google_analytics\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_17173_supersign_cms {
    meta:
        attack_type = "cve_2018_17173"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LG Supersign EZ CMS - Remote Code Execution: LG SuperSign CMS allows remote attackers to execute arbitrary code via the sourceUri parameter to qsr_server/device/getThumbnail."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17173"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17173, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17173.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/qsr_server\/device\/getThumbnail(\/|;|$)/ nocase
        $param0 = /(^|[?&;])targetUri=\/tmp\/thumb\/test\.jpg(&|$)/ nocase
        $param1 = /(^|[?&;])mediaType=image(&|$)/ nocase
        $param2 = /(^|[?&;])scaleType=crop(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_17246_kibana {
    meta:
        attack_type = "cve_2018_17246"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kibana - Local File Inclusion: Kibana versions before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in the Console plugin. An attacker with access to the Kibana Console API could send a request that will attempt to execute JavaScript which could possibly lead to an."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17246"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17246, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17246.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])sense_version=@@SENSE_VERSION(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_17254_jck_editor {
    meta:
        attack_type = "cve_2018_17254"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla! JCK Editor SQL Injection: The JCK Editor component 6.4.4 for Joomla! allows SQL Injection via the jtreelink/dialogs/links.php parent parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17254"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17254, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17254.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/plugins\/editors\/jckeditor\/plugins\/jtreelink\/dialogs\/links\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])extension=menu(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_17283_manageengine_opmanager {
    meta:
        attack_type = "cve_2018_17283"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Zoho ManageEngine OpManager - SQL Injection: Zoho ManageEngine OpManager before 12.3 Build 123196 does not require authentication for /oputilsServlet requests, as demonstrated by a /oputilsServlet?action=getAPIKey request that can be leveraged against Firewall Analyzer to add."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17283"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17283, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17283.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/oputilsServlet(\/|;|$)/ nocase
        $path1 = /\/api\/json\/device\/setManaged(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=getAPIKey(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_17422_dotcms {
    meta:
        attack_type = "cve_2018_17422"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DotCMS < 5.0.2 - Open Redirect: dotCMS before 5.0.2 contains multiple open redirect vulnerabilities via the html/common/forward_js.jsp FORWARD_URL parameter or the html/portlet/ext/common/page_preview_popup.jsp hostname parameter. An attacker can redirect a user to a malicious."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17422"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17422, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17422.yaml"
    strings:
        $path0 = /\/html\/common\/forward_js\.jsp(\/|;|$)/ nocase
        $path1 = /\/html\/portlet\/ext\/common\/page_preview_popup\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_17431_unified_threat_management_fire {
    meta:
        attack_type = "cve_2018_17431"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Comodo Unified Threat Management Web Console - Remote Code Execution: Comodo Firewall & Central Manager (UTM) All Release before 2.7.0 & 1.5.0 are susceptible to a web shell based remote code execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-17431"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17431, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-17431.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/manage/webshell/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_18069_wpml {
    meta:
        attack_type = "cve_2018_18069"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress sitepress-multilingual-cms 3.6.3 - Cross-Site Scripting: WordPress plugin sitepress-multilingual-cms 3.6.3 is vulnerable to cross-site scripting in process_forms via any locale_file_name_ parameter (such as locale_file_name_en) in an authenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18069"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18069, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18069.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])icl_post_action=save_theme_localization(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_18264_dashboard {
    meta:
        attack_type = "cve_2018_18264"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kubernetes Dashboard <1.10.1 - Authentication Bypass: Kubernetes Dashboard before 1.10.1 allows attackers to bypass authentication and use Dashboard's Service Account for reading secrets within the cluster."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18264"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18264, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18264.yaml"
    strings:
        $path0 = /\/api\/v1\/namespaces\/kube-system\/secrets\/kubernetes-dashboard-certs(\/|;|$)/ nocase
        $path1 = /\/k8s\/api\/v1\/namespaces\/kube-system\/secrets\/kubernetes-dashboard-certs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_18570_planon {
    meta:
        attack_type = "cve_2018_18570"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Planon <Live Build 41 - Cross-Site Scripting: Planon before Live Build 41 is vulnerable to cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18570"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18570, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18570.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wicket\/resource\/nl\.planon\.pssm\.dashboard\.cre\.engine\.wicket\.page\.AbstractDashboardPage\/html\/nodata\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_18775_microstrategy_web {
    meta:
        attack_type = "cve_2018_18775"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microstrategy Web 7 - Cross-Site Scripting: Microstrategy Web 7 does not sufficiently encode user-controlled inputs, resulting in cross-site scripting via the Login.asp Msg parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18775"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18775, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18775.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/microstrategy7\/Login\.asp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])Server=Server001(&|$)/ nocase
        $param1 = /(^|[?&;])Project=Project001(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_18777_microstrategy_web {
    meta:
        attack_type = "cve_2018_18777"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microstrategy Web 7 - Local File Inclusion: Microstrategy Web 7 is vulnerable to local file inclusion via '/WebMstr7/servlet/mstrWeb' (in the parameter subpage). Remote authenticated users can bypass intended SecurityManager restrictions and list a parent directory via a /..."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18777"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18777, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18777.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/WebMstr7\/servlet\/mstrWeb(\/|;|$)/ nocase
        $param0 = /(^|[?&;])src=mstrWeb\.3045(&|$)/ nocase
        $param1 = /(^|[?&;])subpage=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_18809_jasperreports_library {
    meta:
        attack_type = "cve_2018_18809"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "TIBCO JasperReports Library - Directory Traversal: The default server implementation of TIBCO Software Inc.'s TIBCO JasperReports Library, TIBCO JasperReports Library Community Edition, TIBCO JasperReports Library for ActiveMatrix BPM, TIBCO JasperReports Server, TIBCO."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-18809"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18809, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-18809.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/jasperserver-pro/reportresource/reportresource/" ascii nocase
        $param0 = /(^|[?&;])resource=net\/sf\/jasperreports\/\.\.\/\.\.\/\.\.\/\.\.\/js\.jdbc\.properties(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19127_phpcms_2008 {
    meta:
        attack_type = "cve_2018_19127"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PHPCMS 2008 - Remote Code Execution via Template Injection: PHPCMS 2008 suffers from an unauthenticated RCE via template injection in type.php, where attacker-supplied content is written into a PHP template cache file, which is then executable."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19127.yaml"
        response_type = "template_eval"
    strings:
        $path0 = /\/data\/cache_template\/rss\.tpl\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19136_domainmod {
    meta:
        attack_type = "cve_2018_19136"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 is vulnerable to reflected cross-site scripting via assets/edit/registrar-account.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19136.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/edit\/registrar-account\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19137_domainmod {
    meta:
        attack_type = "cve_2018_19137"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 is vulnerable to reflected cross-site Scripting via assets/edit/ip-address.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19137.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/edit\/ip-address\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19207_wp_gdpr_compliance {
    meta:
        attack_type = "cve_2018_19207"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP GDPR Compliance < 1.4.3 - Unauthenticated Call Any Action or Update Any Option: The WP GDPR Compliance plugin allows unauthenticated users to execute any action and update any database value. This vulnerability is due to the lack of proper validation in the Includes/Ajax.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19207, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19207.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=wpgdprc_process_action(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19287_ninja_forms {
    meta:
        attack_type = "cve_2018_19287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Ninja Forms <3.3.18 - Cross-Site Scripting: WordPress Ninja Forms plugin before 3.3.18 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in includes/Admin/Menus/Submissions.php via the begin_date, end_date, or form_id parameters.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19287.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=nf_sub(&|$)/ nocase
        $param1 = /(^|[?&;])filter_action=Filter(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19365_streaming_engine {
    meta:
        attack_type = "cve_2018_19365"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wowza Streaming Engine Manager 4.7.4.01 - Directory Traversal: Wowza Streaming Engine 4.7.4.01 allows traversal of the directory structure and retrieval of a file via a remote, specifically crafted HTTP request to the REST API."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19365"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19365, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19365.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/enginemanager\/server\/logs\/download(\/|;|$)/ nocase
        $param0 = /(^|[?&;])logType=error(&|$)/ nocase
        $param1 = /(^|[?&;])logName=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param2 = /(^|[?&;])logSource=engine(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19386_database_performance_analyzer {
    meta:
        attack_type = "cve_2018_19386"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SolarWinds Database Performance Analyzer 11.1.457 - Cross-Site Scripting: SolarWinds Database Performance Analyzer 11.1.457 contains a reflected cross-site scripting vulnerability in its idcStateError component, where the page parameter is reflected into the HREF of the 'Try."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19386"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19386, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19386.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/iwc\/idcStateError\.iwc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19410_prtg_network_monitor {
    meta:
        attack_type = "cve_2018_19410"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "PRTG Network Monitor - Local File Inclusion: PRTG Network Monitor before 18.2.40.1683 allows remote unauthenticated attackers to create users with read-write privileges (including administrator). A remote unauthenticated user can craft an HTTP request and override attributes of."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19410"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19410, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19410.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])file=\/api\/addusers\.htm(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19439_secure_global_desktop {
    meta:
        attack_type = "cve_2018_19439"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Secure Global Desktop Administration Console 4.4 - Cross-Site Scripting: Oracle Secure Global Desktop Administration Console 4.4 contains a reflected cross-site scripting vulnerability in helpwindow.jsp via all parameters, as demonstrated by the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19439"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19439, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19439.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/sgdadmin\/faces\/com_sun_web_ui\/help\/helpwindow\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19749_domainmod {
    meta:
        attack_type = "cve_2018_19749"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 contains a cross-site scripting vulnerability via assets/add/account-owner.php Owner name field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19749"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19749, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19749.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/add\/account-owner\.php(\/|;|$)/ nocase
        $path1 = /\/assets\/account-owners\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19751_domainmod {
    meta:
        attack_type = "cve_2018_19751"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 contains a cross-site scripting vulnerability via /admin/ssl-fields/add.php Display Name, Description & Notes field parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19751"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19751, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19751.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/ssl-fields\/add\.php(\/|;|$)/ nocase
        $path1 = "/admin/ssl-fields/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19752_domainmod {
    meta:
        attack_type = "cve_2018_19752"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD through 4.11.01 contains a cross-site scripting vulnerability via the assets/add/registrar.php notes field for Registrar."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19752"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19752, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19752.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/add\/registrar\.php(\/|;|$)/ nocase
        $path1 = /\/assets\/registrars\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19753_tarantella_enterprise {
    meta:
        attack_type = "cve_2018_19753"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tarantella Enterprise <3.11 - Local File Inclusion: Tarantella Enterprise versions prior to 3.11 are susceptible to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19753"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19753, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19753.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/tarantella/cgi-bin/secure/ttawlogin.cgi/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_19892_domainmod {
    meta:
        attack_type = "cve_2018_19892"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD 4.11.01 contains a cross-site scripting vulnerability via /domain//admin/dw/add-server.php DisplayName parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19892"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19892, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19892.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/dw\/servers\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])new_protocol=https(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_19915_domainmod {
    meta:
        attack_type = "cve_2018_19915"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD <=4.11.01 - Cross-Site Scripting: DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the assets/edit/host.php Web Host Name or Web Host URL field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-19915"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19915, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-19915.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/hosting\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20009_domainmod {
    meta:
        attack_type = "cve_2018_20009"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/ssl-provider.php ssl-provider-name and ssl-provider's-url parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20009"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20009, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20009.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/add\/ssl-provider\.php(\/|;|$)/ nocase
        $path1 = /\/assets\/ssl-providers\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20010_domainmod {
    meta:
        attack_type = "cve_2018_20010"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/ssl-provider-account.php Username field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20010"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20010, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20010.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/add\/ssl-provider-account\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20011_domainmod {
    meta:
        attack_type = "cve_2018_20011"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.11.01 - Cross-Site Scripting: DomainMOD through version 4.11.01 is vulnerable to cross-site scripting via the /assets/add/category.php CatagoryName and StakeHolder parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20011"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20011, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20011.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/add\/category\.php(\/|;|$)/ nocase
        $path1 = /\/assets\/categories\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20462_jsmol2wp {
    meta:
        attack_type = "cve_2018_20462"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress JSmol2WP <=1.07 - Cross-Site Scripting: WordPress JSmol2WP version 1.07 and earlier is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the jsmol.php data parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20462"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20462, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20462.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])mimetype=text\/html; charset=utf-8(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_20470_sahi_pro {
    meta:
        attack_type = "cve_2018_20470"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tyto Sahi pro 7.x/8.x - Local File Inclusion: Tyto Sahi Pro versions through 7.x.x and 8.0.0 are susceptible to a local file inclusion vulnerability in the web reports module which can allow an outside attacker to view contents of sensitive files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20470"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20470, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20470.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/_s_\/dyn\/Log_highlight(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20608_imcat {
    meta:
        attack_type = "cve_2018_20608"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Imcat 4.4 - Phpinfo Configuration: Imcat 4.4 allows remote attackers to read phpinfo output via the root/tools/adbug/binfo.php?phpinfo1 URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20608"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20608, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20608.yaml"
    strings:
        $path0 = /\/imcat\/root\/tools\/adbug\/binfo\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_20824_jira {
    meta:
        attack_type = "cve_2018_20824"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Jira WallboardServlet <7.13.1 - Cross-Site Scripting: The WallboardServlet resource in Jira before version 7.13.1 allows remote attackers to inject arbitrary HTML or JavaScript via a cross-site scripting vulnerability in the cyclePeriod parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20824.yaml"
        response_type = "xss"
    strings:
        $path0 = "/plugins/servlet/Wallboard/" ascii nocase
        $param0 = /(^|[?&;])cyclePeriod=alert\(document\.domain\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_20985_wp_payeezy_pay {
    meta:
        attack_type = "cve_2018_20985"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Payeezy Pay <=2.97 - Local File Inclusion: WordPress Plugin WP Payeezy Pay is prone to a local file inclusion vulnerability because it fails to sufficiently verify user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-20985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20985.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-payeezy-pay\/donate\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])x_login=\.\.\/\.\.\/\.\.\/wp-config(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_25114_oscommerce_2_3_4_1 {
    meta:
        attack_type = "cve_2018_25114"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "osCommerce 2.3.4.1 - Remote Code Execution: osCommerce Online Merchant 2.3.4.1 contains a remote code execution caused by insecure default configuration and missing authentication in the installer workflow, letting unauthenticated attackers execute arbitrary PHP code via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-25114"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-25114, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-25114.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/install\/includes\/configure\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_2791_webcenter_sites {
    meta:
        attack_type = "cve_2018_2791"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Fusion Middleware WebCenter Sites - Cross-Site Scripting: The Oracle WebCenter Sites component of Oracle Fusion Middleware is susceptible to multiple instances of cross-site scripting that could allow unauthenticated attackers with network access via HTTP to compromise."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-2791"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-2791, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-2791.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])pagename=OpenMarket\/Gator\/FlexibleAssets\/AssetMaker\/confirmmakeasset(&|$)/ nocase
        $param1 = /(^|[?&;])pagename=OpenMarket\/Xcelerate\/UIFramework\/LoginError(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_2894_weblogic_server {
    meta:
        attack_type = "cve_2018_2894"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Oracle WebLogic Server - Remote Code Execution: The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services) is susceptible to a remote code execution vulnerability that is easily exploitable and could allow unauthenticated attackers with."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-2894"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-2894, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-2894.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ws_utc\/resources\/setting\/options(\/|;|$)/ nocase
        $path1 = /\/ws_utc\/resources\/setting\/keystore(\/|;|$)/ nocase
        $path2 = "/ws_utc/css/config/keystore/" ascii nocase
        $param0 = /(^|[?&;])setting_id=general(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_3167_application_management_pack {
    meta:
        attack_type = "cve_2018_3167"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle E-Business Suite - Blind SSRF: Oracle E-Business Suite, Application Management Pack component (User Monitoring subcomponent), is susceptible to blind server-side request forgery. An attacker with network access via HTTP can gain read access to a subset of data, connect."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-3167"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-3167, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-3167.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/OA_HTML\/lcmServiceController\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_3238_webcenter_sites {
    meta:
        attack_type = "cve_2018_3238"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Fusion Middleware WebCenter Sites 11.1.1.8.0 - Cross-Site Scripting: The Oracle WebCenter Sites 11.1.1.8.0 component of Oracle Fusion Middleware is impacted by easily exploitable cross-site scripting vulnerabilities that allow high privileged attackers with network."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-3238"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-3238, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-3238.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])pagename=OpenMarket\/Gator\/FlexibleAssets\/AssetMaker\/complexassetmaker(&|$)/ nocase
        $param1 = /(^|[?&;])pagename=OpenMarket\/Xcelerate\/Actions\/Security\/NoXceleditor(&|$)/ nocase
        $param2 = /(^|[?&;])pagename=OpenMarket\/Xcelerate\/Actions\/Security\/ProcessLoginRequest(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_3760_cloudforms {
    meta:
        attack_type = "cve_2018_3760"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ruby On Rails - Local File Inclusion: Ruby On Rails is vulnerable to local file inclusion caused by secondary decoding in Sprockets 3.7.1 and lower versions. An attacker can use %252e%252e/ to access the root directory and read or execute any file on the target server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-3760"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-3760, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-3760.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/%2e%2e\/%2e%2e\/%2e%2e\/%2e%2e\/%2e%2e\/%2e%2e\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_3810_smart_google_code_inserter {
    meta:
        attack_type = "cve_2018_3810"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Oturia WordPress Smart Google Code Inserter <3.5 - Authentication Bypass: Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-3810"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-3810, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-3810.yaml"
    strings:
        $param0 = /(^|[?&;])page=smartcode(&|$)/ nocase
        $param1 = /(^|[?&;])button=Save Changes(&|$)/ nocase
        $param2 = /(^|[?&;])action=savegooglecode(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_5316_sagepay_server_gateway_for_woo {
    meta:
        attack_type = "cve_2018_5316"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress SagePay Server Gateway for WooCommerce <1.0.9 - Cross-Site Scripting: WordPress SagePay Server Gateway for WooCommerce before 1.0.9 is vulnerable to cross-site scripting via the includes/pages/redirect.php page parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-5316"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5316, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-5316.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/sagepay-server-gateway-for-woocommerce\/includes\/pages\/redirect\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_6008_jtag_members_directory {
    meta:
        attack_type = "cve_2018_6008"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Jtag Members Directory 5.3.7 - Local File Inclusion: Joomla! Jtag Members Directory 5.3.7 is vulnerable to local file inclusion via the download_file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6008"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6008, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6008.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])option=com_jtagmembersdirectory(&|$)/ nocase
        $param1 = /(^|[?&;])task=attachment(&|$)/ nocase
        $param2 = /(^|[?&;])download_file=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_6200_vbulletin {
    meta:
        attack_type = "cve_2018_6200"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "vBulletin - Open Redirect: vBulletin 3.x.x and 4.2.x through 4.2.5 contains an open redirect vulnerability via the redirector.php URL parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6200"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6200, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6200.yaml"
    strings:
        $path0 = /\/redirector\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_6530_dir_860l_firmware {
    meta:
        attack_type = "cve_2018_6530"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "D-Link - Unauthenticated Remote Code Execution: OS command injection vulnerability in soap.cgi (soapcgi_main in cgibin) in D-Link DIR-880L DIR-880L_REVA_FIRMWARE_PATCH_1.08B04 and previous versions, DIR-868L DIR868LA1_FW112b04 and previous versions, DIR-65L."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6530"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6530, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6530.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])service=whatever-control;curl(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_6605_zh_baidumap {
    meta:
        attack_type = "cve_2018_6605"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla! Component Zh BaiduMap 3.0.0.1 - SQL Injection: SQL Injection exists in the Zh BaiduMap 3.0.0.1 component for Joomla! via the id parameter in a getPlacemarkDetails, getPlacemarkHoverText, getPathHoverText, or getPathDetails request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6605"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6605, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6605.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])option=com_zhbaidumap(&|$)/ nocase
        $param1 = /(^|[?&;])task=getPlacemarkDetails(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_6882_collaboration_server {
    meta:
        attack_type = "cve_2018_6882"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Zimbra Collaboration Suite - Cross-site Scripting: Cross-site scripting (XSS) vulnerability in the ZmMailMsgView.getAttachmentLinkHtml function in Zimbra Collaboration Suite (ZCS) before 8.7 Patch 1 and 8.8.x before 8.8.7 might allow remote attackers to inject arbitrary web."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6882"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6882, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6882.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/service\/soap\/SearchConvRequest(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_6910_dedecms {
    meta:
        attack_type = "cve_2018_6910"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DedeCMS 5.7 - Path Disclosure: DedeCMS 5.7 allows remote attackers to discover the full path via a direct request for include/downmix.inc.php or inc/inc_archives_functions.php"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6910"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6910, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6910.yaml"
    strings:
        $path0 = /\/include\/downmix\.inc\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_6961_nsx_sd_wan_edge {
    meta:
        attack_type = "cve_2018_6961"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "VMware NSX SD-WAN Edge - Command Injection: VMware NSX SD-WAN Edge (formerly VeloCloud Edge) before 3.1.2 contains an unauthenticated command injection in the local web UI diagnostic tools (Ping/Traceroute). This template detects it reliably by injecting 'id', 'whoami', and a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-6961"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6961, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-6961.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/scripts\/ajaxPortal\.lua(\/|;|$)/ nocase
        $param0 = /(^|[?&;])test=TRACEROUTE(&|$)/ nocase
        $param1 = /(^|[?&;])_cmd=run_diagnostic(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_7193_osticket {
    meta:
        attack_type = "cve_2018_7193"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "osTicket < 1.10.2 - Cross-Site Scripting: Cross-site scripting (XSS) vulnerability in /scp/directory.php in Enhancesoft osTicket before 1.10.2 allows remote attackers to inject arbitrary web script or HTML via the 'order' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-7193"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7193, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-7193.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/scp\/directory\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_7251_anchor {
    meta:
        attack_type = "cve_2018_7251"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Anchor CMS 0.12.3 - Error Log Exposure: Anchor CMS 0.12.3 is susceptible to an error log exposure vulnerability due to an issue in config/error.php. The error log is exposed at an errors.log URI, and contains MySQL credentials if a MySQL error (such as 'Too many connections')."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-7251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7251, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-7251.yaml"
    strings:
        $path0 = /\/anchor\/errors\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_7314_prayercenter {
    meta:
        attack_type = "cve_2018_7314"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla! Component PrayerCenter 3.0.2 - SQL Injection: SQL Injection exists in the PrayerCenter 3.0.2 component for Joomla! via the sessionid parameter, a different vulnerability than CVE-2008-6429."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-7314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-7314.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])option=com_prayercenter(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_7422_site_editor {
    meta:
        attack_type = "cve_2018_7422"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Site Editor <=1.1.1 - Local File Inclusion: WordPress Site Editor through 1.1.1 allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-7422"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7422, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-7422.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/site-editor\/editor\/extensions\/pagebuilder\/includes\/ajax_shortcode_pattern\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ajax_path=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
        $param1 = /(^|[?&;])ajax_path=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_7662_couch {
    meta:
        attack_type = "cve_2018_7662"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CouchCMS <= 2.0 - Path Disclosure: CouchCMS <= 2.0 allows remote attackers to discover the full path via a direct request to includes/mysql2i/mysql2i.func.php or addons/phpmailer/phpmailer.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-7662"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7662, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-7662.yaml"
    strings:
        $path0 = /\/includes\/mysql2i\/mysql2i\.func\.php(\/|;|$)/ nocase
        $path1 = /\/addons\/phpmailer\/phpmailer\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_8006_activemq {
    meta:
        attack_type = "cve_2018_8006"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache ActiveMQ <=5.15.5 - Cross-Site Scripting: Apache ActiveMQ versions 5.0.0 to 5.15.5 are vulnerable to cross-site scripting via the web based administration console on the queue.jsp page. The root cause of this issue is improper data filtering of the QueueFilter parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-8006"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8006, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-8006.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/queues\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_8033_ofbiz {
    meta:
        attack_type = "cve_2018_8033"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache OFBiz - XML External Entity Injection: In Apache OFBiz 16.11.01 to 16.11.04, the OFBiz HTTP engine (org.apache.ofbiz.service.engine.HttpEngine.java) handles requests for HTTP services via the /webtools/control/httpService endpoint. Both POST and GET requests to the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-8033"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8033, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-8033.yaml"
    strings:
        $path0 = /\/webtools\/control\/httpService(\/|;|$)/ nocase
        $param0 = /(^|[?&;])serviceName=createPartyGroup(&|$)/ nocase
        $param1 = /(^|[?&;])serviceMode=sync(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2018_8719_wp_security_audit_log {
    meta:
        attack_type = "cve_2018_8719"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WP Security Audit Log 3.1.1 - Information Disclosure: WordPress WP Security Audit Log 3.1.1 plugin is susceptible to information disclosure. Access to wp-content/uploads/wp-security-audit-log/* files is not restricted. An attacker can obtain sensitive information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-8719"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8719, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-8719.yaml"
    strings:
        $path0 = "/wp-content/uploads/wp-security-audit-log/failed-logins/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_8770_razor {
    meta:
        attack_type = "cve_2018_8770"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cobub Razor 0.8.0 - Information Disclosure: Cobub Razor 0.8.0 is susceptible to information disclosure via generate.php, controllers/getConfigTest.php, controllers/getUpdateTest.php, controllers/postclientdataTest.php, controllers/posterrorTest.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-8770"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8770, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-8770.yaml"
    strings:
        $path0 = /\/tests\/generate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_8823_responsive_mega_menu_pro {
    meta:
        attack_type = "cve_2018_8823"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop Responsive Mega Menu Module - Remote Code Execution: The 'Responsive Mega Menu' module for PrestaShop is prone to a remote code execution and SQL injection vulnerability. modules/bamegamenu/ajax_phpcode.php in the Responsive Mega Menu (Horizontal+Vertical+Dropdown)."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-8823"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8823, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-8823.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/modules\/bamegamenu\/ajax_phpcode\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_9118_wp_background_takeover_adverti {
    meta:
        attack_type = "cve_2018_9118"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress 99 Robots WP Background Takeover Advertisements <=4.1.4 - Local File Inclusion: WordPress 99 Robots WP Background Takeover Advertisements 4.1.4 is susceptible to local file inclusion via exports/download.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-9118"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-9118, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-9118.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wpsite-background-takeover\/exports\/download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_9205_avatar_uploader {
    meta:
        attack_type = "cve_2018_9205"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Drupal avatar_uploader v7.x-1.0-beta8 - Local File Inclusion: In avatar_uploader v7.x-1.0-beta8 the view.php program doesn't restrict file paths, allowing unauthenticated users to retrieve arbitrary files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-9205"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-9205, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-9205.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/sites\/all\/modules\/avatar_uploader\/lib\/demo\/view\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2018_9995_tbk_dvr4216_firmware {
    meta:
        attack_type = "cve_2018_9995"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TBK DVR4104/DVR4216 Devices - Authentication Bypass: TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2018-9995"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-9995, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-9995.yaml"
    strings:
        $path0 = /\/device\.rsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}
