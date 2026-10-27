// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2000_0760_tomcat {
    meta:
        attack_type = "cve_2000_0760"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jakarta Tomcat 3.1 and 3.0 - Information Disclosure: Jakarta Tomcat 3.1 and 3.0 under Apache contain a vulnerability in the Snoop servlet that reveals sensitive system information when a remote attacker requests a nonexistent URL with a .snp extension, exploit requires remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2000-0760"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2000-0760, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2000/CVE-2000-0760.yaml"
    strings:
        $path0 = "/examples/jsp/snp/anything.snp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2001_0537_ios {
    meta:
        attack_type = "cve_2001_0537"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco IOS HTTP Configuration - Authentication Bypass: HTTP server for Cisco IOS 11.3 to 12.2 allows attackers to bypass authentication and execute arbitrary commands, when local authorization is being used, by specifying a high access level in the URL."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2001-0537"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2001-0537, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2001/CVE-2001-0537.yaml"
    strings:
        $path0 = "/level/16/exec/show/config/CR" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2002_1131_squirrelmail {
    meta:
        attack_type = "cve_2002_1131"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SquirrelMail 1.2.6/1.2.7 - Cross-Site Scripting: The Virtual Keyboard plugin for SquirrelMail 1.2.6/1.2.7 is prone to a cross-site scripting vulnerability because it fails to properly sanitize user-supplied input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2002-1131"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2002-1131, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2002/CVE-2002-1131.yaml"
        response_type = "xss"
    strings:
        $path0 = "/src/addressbook.php" ascii nocase
        $path1 = "/src/options.php" ascii nocase
        $param0 = "mailbox=INBOX" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2004_0519_propack {
    meta:
        attack_type = "cve_2004_0519"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SquirrelMail 1.4.x - Folder Name Cross-Site Scripting: Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary script and possibly steal authentication information via multiple attack vectors, including the mailbox."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2004-0519"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2004-0519, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2004/CVE-2004-0519.yaml"
        response_type = "xss"
    strings:
        $path0 = "/mail/src/compose.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2005_2428_lotus_domino {
    meta:
        attack_type = "cve_2005_2428"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Lotus Domino R5 and R6 WebMail - Information Disclosure: Lotus Domino R5 and R6 WebMail with 'Generate HTML for all fields' enabled (which is by default) allows remote attackers to read the HTML source to obtain sensitive information including the password hash in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2005-2428"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2005-2428, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2005/CVE-2005-2428.yaml"
    strings:
        $path0 = "/names.nsf/People" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2005_3128_squirrelmail_address_add_1_4_2 {
    meta:
        attack_type = "cve_2005_3128"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SquirrelMail Address Add 1.4.2 - Cross-Site Scripting: SquirrelMail Address Add 1.4.2 plugin contains a cross-site scripting vulnerability. It fails to properly sanitize user-supplied input, thus allowing an attacker to execute arbitrary script in the browser of an unsuspecting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2005-3128"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2005-3128, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2005/CVE-2005-3128.yaml"
        response_type = "xss"
    strings:
        $path0 = "/plugins/address_add/add.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2005_3344_horde {
    meta:
        attack_type = "cve_2005_3344"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Horde Groupware Unauthenticated Admin Access: Horde Groupware contains an administrative account with a blank password, which allows remote attackers to gain access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2005-3344"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2005-3344, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2005/CVE-2005-3344.yaml"
    strings:
        $path0 = "/horde/admin/user.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2005_3634_sap_web_application_server {
    meta:
        attack_type = "cve_2005_3634"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SAP Web Application Server 6.x/7.0 - Open Redirect: frameset.htm in the BSP runtime in SAP Web Application Server (WAS) 6.10 through 7.00 allows remote attackers to log users out and redirect them to arbitrary web sites via a close command in the sap-sessioncmd parameter and a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2005-3634"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2005-3634, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2005/CVE-2005-3634.yaml"
        response_type = "xss"
    strings:
        $path0 = "/sap/bc/BSp/sap/menu/fameset.htm" ascii nocase
        $param0 = "sap--essioncmd=close" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2006_2842_squirrelmail {
    meta:
        attack_type = "cve_2006_2842"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Squirrelmail <=1.4.6 - Local File Inclusion: SquirrelMail 1.4.6 and earlier versions are susceptible to a PHP local file inclusion vulnerability in functions/plugin.php if register_globals is enabled and magic_quotes_gpc is disabled. This allows remote attackers to execute."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2006-2842"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2006-2842, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2006/CVE-2006-2842.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/src/redirect.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2007_0885_rainbow_zen {
    meta:
        attack_type = "cve_2007_0885"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Rainbow.Zen - Cross-Site Scripting: Jira Rainbow.Zen contains a cross-site scripting vulnerability via Jira/secure/BrowseProject.jspa which allows remote attackers to inject arbitrary web script or HTML via the id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2007-0885"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-0885, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2007/CVE-2007-0885.yaml"
        response_type = "xss"
    strings:
        $path0 = "/jira/secure/BrowseProject.jspa" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2007_3010_omnipcx {
    meta:
        attack_type = "cve_2007_3010"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Alcatel-Lucent OmniPCX - Remote Command Execution: The OmniPCX web interface has a script 'masterCGI' with a remote command execution vulnerability via the 'user' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2007-3010"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-3010, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2007/CVE-2007-3010.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/masterCGI" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2007_4504_rsfiles {
    meta:
        attack_type = "cve_2007_4504"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! RSfiles <=1.0.2 - Local File Inclusion: Joomla! RSfiles 1.0.2 and earlier is susceptible to local file inclusion in index.php in the RSfiles component (com_rsfiles). This could allow remote attackers to arbitrarily read files via a .. (dot dot) in the path parameter in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2007-4504"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-4504, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2007/CVE-2007-4504.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "task=files.display" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2007_5728_phppgadmin {
    meta:
        attack_type = "cve_2007_5728"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpPgAdmin <=4.1.1 - Cross-Site Scripting: phpPgAdmin 3.5 to 4.1.1, and possibly 4.1.2, is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via certain input available in PHP_SELF in (1) redirect.php, possibly related to (2)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2007-5728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-5728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2007/CVE-2007-5728.yaml"
        response_type = "xss"
    strings:
        $param0 = "subject=server" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2008_1059_sniplets_plugin {
    meta:
        attack_type = "cve_2008_1059"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Sniplets 1.1.2 - Local File Inclusion: PHP remote file inclusion vulnerability in modules/syntax_highlight.php in the Sniplets 1.1.2 and 1.2.2 plugin for WordPress allows remote attackers to execute arbitrary PHP code via a URL in the libpath parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-1059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-1059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-1059.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/sniplets/modules/syntax_highlight.php" ascii nocase
        $param0 = "libpath=../../../../wp-config.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2008_1061_sniplets_plugin {
    meta:
        attack_type = "cve_2008_1061"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Sniplets <=1.2.2 - Cross-Site Scripting: WordPress Sniplets 1.1.2 and 1.2.2 plugin contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the text parameter to warning.php, notice.php, and inset.php in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-1061"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-1061, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-1061.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/sniplets/view/sniplets/warning.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2008_1547_exchange_server {
    meta:
        attack_type = "cve_2008_1547"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microsoft OWA Exchange Server 2003 - 'redir.asp' Open Redirection: Open redirect vulnerability in exchweb/bin/redir.asp in Microsoft Outlook Web Access (OWA) for Exchange Server 2003 SP2 (aka build 6.5.7638) allows remote attackers to redirect users to arbitrary web sites and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-1547"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-1547, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-1547.yaml"
    strings:
        $path0 = "/exchweb/bin/redir.asp" ascii nocase
        $path1 = "/CookieAuth.dll" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2008_4668_com_imagebrowser {
    meta:
        attack_type = "cve_2008_4668"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla! Image Browser 0.1.5 rc2 - Local File Inclusion: Joomla! Image Browser 0.1.5 rc2 is susceptible to local file inclusion via com_imagebrowser which could allow remote attackers to include and execute arbitrary local files via a .. (dot dot) in the folder parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-4668"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-4668, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-4668.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_imagebrowser" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2008_4764_com_extplorer {
    meta:
        attack_type = "cve_2008_4764"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! <=2.0.0 RC2 - Local File Inclusion: Joomla! 2.0.0 RC2 and earlier are susceptible to local file inclusion in the eXtplorer module (com_extplorer) that allows remote attackers to read arbitrary files via a .. (dot dot) in the dir parameter in a show_error action."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-4764"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-4764, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-4764.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_extplorer" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2008_5587_phppgadmin {
    meta:
        attack_type = "cve_2008_5587"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpPgAdmin <=4.2.1 - Local File Inclusion: phpPgAdmin 4.2.1 is vulnerable to local file inclusion in libraries/lib.inc.php when register globals is enabled. Remote attackers can read arbitrary files via a .. (dot dot) in the _language parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-5587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-5587, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-5587.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/phpPgAdmin/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2008_6080_com_ionfiles {
    meta:
        attack_type = "cve_2008_6080"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! ionFiles 4.4.2 - Local File Inclusion: Joomla! ionFiles 4.4.2 is susceptible to local file inclusion in download.php in the ionFiles (com_ionfiles) that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-6080"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-6080, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-6080.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/components/com_ionfiles/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2008_6172_rwcards {
    meta:
        attack_type = "cve_2008_6172"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component RWCards 3.0.11 - Local File Inclusion: A directory traversal vulnerability in captcha/captcha_image.php in the RWCards (com_rwcards) 3.0.11 component for Joomla! when magic_quotes_gpc is disabled allows remote attackers to include and execute arbitrary local."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-6172"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-6172, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-6172.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/components/com_rwcards/captcha/captcha_image.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2008_6222_pro_desk_support_center {
    meta:
        attack_type = "cve_2008_6222"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! ProDesk 1.0/1.2 - Local File Inclusion: Joomla! Pro Desk Support Center (com_pro_desk) component 1.0 and 1.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the include_file parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-6222"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-6222, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-6222.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "include_file=../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2008_6668_nweb2fax {
    meta:
        attack_type = "cve_2008_6668"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "nweb2fax <=0.2.7 - Local File Inclusion: nweb2fax 0.2.7 and earlier allow remote attackers to read arbitrary files via the id parameter submitted to comm.php and the var_filename parameter submitted to viewrq.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2008-6668"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-6668, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2008/CVE-2008-6668.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/viewrq.php" ascii nocase
        $param0 = "var_filename=../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_0545_zeroshell {
    meta:
        attack_type = "cve_2009_0545"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZeroShell <= 1.0beta11 Remote Code Execution: ZeroShell 1.0beta11 and earlier via cgi-bin/kerbynet allows remote attackers to execute arbitrary commands through shell metacharacters in the type parameter in a NoAuthREQ x509List action."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-0545"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-0545, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-0545.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "Section=NoAuthREQ" ascii nocase
        $param1 = "Action=x509List" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_0932_horde {
    meta:
        attack_type = "cve_2009_0932"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Horde/Horde Groupware - Local File Inclusion: Horde before 3.2.4 and 3.3.3 and Horde Groupware before 1.1.5 are susceptible to local file inclusion in framework/Image/Image.php because it allows remote attackers to include and execute arbitrary local files via directory."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-0932"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-0932, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-0932.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/horde/util/barcode.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2009_1151_phpmyadmin {
    meta:
        attack_type = "cve_2009_1151"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "PhpMyAdmin Scripts - Remote Code Execution: PhpMyAdmin Scripts 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 are susceptible to a remote code execution in setup.php that allows remote attackers to inject arbitrary PHP code into a configuration file via the save action. Combined."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-1151"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1151, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-1151.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/scripts/setup.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2009_1496_joomla {
    meta:
        attack_type = "cve_2009_1496"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Cmimarketplace 0.1 - Local File Inclusion: Joomla! Cmimarketplace 0.1 is susceptible to local file inclusion because com_cmimarketplace allows remote attackers to list arbitrary directories via a .. (dot dot) in the viewit parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-1496"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1496, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-1496.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_cmimarketplace" ascii nocase
        $param1 = "viewit=/../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_1558_wvc54gca {
    meta:
        attack_type = "cve_2009_1558"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco Linksys WVC54GCA 1.00R22/1.00R24 - Local File Inclusion: Cisco Linksys WVC54GCA 1.00R22/1.00R24 is susceptible to local file inclusion in adm/file.cgi because it allows remote attackers to read arbitrary files via a %2e. (encoded dot dot) or an absolute pathname in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-1558"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1558, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-1558.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "next_file=/etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_1872_coldfusion {
    meta:
        attack_type = "cve_2009_1872"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adobe Coldfusion <=8.0.1 - Cross-Site Scripting: Adobe ColdFusion Server 8.0.1 and earlier contain multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via (1) the startRow parameter to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-1872"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1872, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-1872.yaml"
        response_type = "xss"
    strings:
        $path0 = "/CFIDE/wizards/common/_logintowizard.cfm" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2009_2015_joomla {
    meta:
        attack_type = "cve_2009_2015"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! MooFAQ 1.0 - Local File Inclusion: Joomla! Ideal MooFAQ 1.0 via com_moofaq allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter (local file inclusion)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-2015"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-2015, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-2015.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/components/com_moofaq/includes/file_includer.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2009_2100_joomla {
    meta:
        attack_type = "cve_2009_2100"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! JoomlaPraise Projectfork 2.0.10 - Local File Inclusion: Joomla! JoomlaPraise Projectfork (com_projectfork) 2.0.10 allows remote attackers to read arbitrary files via local file inclusion in the section parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-2100"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-2100, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-2100.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_projectfork" ascii nocase
        $param1 = "section=../../../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_3053_joomla {
    meta:
        attack_type = "cve_2009_3053"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Agora 3.0.0b - Local File Inclusion: Joomla! Agora 3.0.0b (com_agora) allows remote attackers to include and execute arbitrary local files via local file inclusion in the action parameter to the avatars page, reachable through index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-3053"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3053, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-3053.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "task=profile" ascii nocase
        $param1 = "page=avatars" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_4202_joomla {
    meta:
        attack_type = "cve_2009_4202"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Omilen Photo Gallery 0.5b - Local File Inclusion: Joomla! Omilen Photo Gallery (com_omphotogallery) component Beta 0.5 allows remote attackers to include and execute arbitrary local files via directory traversal sequences in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-4202"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-4202, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-4202.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_omphotogallery" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2009_4223_kr_php_web_content_server {
    meta:
        attack_type = "cve_2009_4223"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "KR-Web <=1.1b2 - Remote File Inclusion: KR-Web 1.1b2 and prior contain a remote file inclusion vulnerability via adm/krgourl.php, which allows remote attackers to execute arbitrary PHP code via a URL in the DOCUMENT_ROOT parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-4223"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-4223, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-4223.yaml"
    strings:
        $path0 = "/adm/krgourl.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2009_5114_webglimpse {
    meta:
        attack_type = "cve_2009_5114"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WebGlimpse 2.18.7 - Directory Traversal: A directory traversal vulnerability in wgarcmin.cgi in WebGlimpse 2.18.7 and earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the DOC parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2009-5114"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-5114, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2009/CVE-2009-5114.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wgarcmin.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_0157_joomla {
    meta:
        attack_type = "cve_2010_0157"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component com_biblestudy - Local File Inclusion: A directory traversal vulnerability in the Bible Study (com_biblestudy) component 6.1 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter in a."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0157"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0157, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0157.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_biblestudy" ascii nocase
        $param1 = "view=studieslist" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0219_axis2 {
    meta:
        attack_type = "cve_2010_0219"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Axis2 Default Login: Apache Axis2, as used in dswsbobje.war in SAP BusinessObjects Enterprise XI 3.2, CA ARCserve D2D r15, and other products, has a default password of axis2 for the admin account, which makes it easier for remote attackers to execute arbitrary code by."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0219.yaml"
    strings:
        $path0 = "/axis2-admin/login" ascii nocase
        $path1 = "/axis2/axis2-admin/login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_0467_com_ccnewsletter {
    meta:
        attack_type = "cve_2010_0467"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component CCNewsLetter - Local File Inclusion: A directory traversal vulnerability in the ccNewsletter (com_ccnewsletter) component 1.0.5 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter in a ccnewsletter action."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0467.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_ccnewsletter" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0696_jw_allvideos {
    meta:
        attack_type = "cve_2010_0696"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Jw_allVideos - Arbitrary File Retrieval: A directory traversal vulnerability in includes/download.php in the JoomlaWorks AllVideos (Jw_allVideos) plugin 3.0 through 3.2 for Joomla! allows remote attackers to read arbitrary files via a ./../.../ (modified dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0696"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0696, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0696.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/plugins/content/jw_allvideos/includes/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_0738_jboss_enterprise_application_p {
    meta:
        attack_type = "cve_2010_0738"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "JBoss JMX/Web Console - Authentication Bypass via HTTP Verb Tampering: JBoss EAP 4.2 (before 4.2.0.CP09) and 4.3 (before 4.3.0.CP08) only enforce authentication for GET/POST on the JMX and Web consoles because the web.xml security-constraint enumerates only those verbs in."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0738"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0738, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0738.yaml"
    strings:
        $path0 = "/jmx-console/HtmlAdaptor" ascii nocase
        $path1 = "/jmx-console/.;/HtmlAdaptor" ascii nocase
        $param0 = "action=inspectMBean" ascii nocase
        $param1 = "name=jboss.system:type=ServerInfo" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0759_scriptegrator_plugin {
    meta:
        attack_type = "cve_2010_0759"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Plugin Core Design Scriptegrator - Local File Inclusion: A directory traversal vulnerability in plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php in the Core Design Scriptegrator plugin 1.4.1 for Joomla! allows remote attackers to read, and possibly."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0759"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0759, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0759.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php" ascii nocase
        $param0 = "files[]=/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0942_com_jvideodirect {
    meta:
        attack_type = "cve_2010_0942"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_jvideodirect - Directory Traversal: Directory traversal vulnerability in the jVideoDirect (com_jvideodirect) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0942"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0942, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0942.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jvideodirect" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0943_com_jashowcase {
    meta:
        attack_type = "cve_2010_0943"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_jashowcase - Directory Traversal: A directory traversal vulnerability in the JA Showcase (com_jashowcase) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter in a jashowcase action to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0943.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jashowcase" ascii nocase
        $param1 = "view=jashowcase" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0944_com_jcollection {
    meta:
        attack_type = "cve_2010_0944"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_jcollection - Directory Traversal: A directory traversal vulnerability in the JCollection (com_jcollection) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0944"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0944, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0944.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jcollection" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0972_com_gcalendar {
    meta:
        attack_type = "cve_2010_0972"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component com_gcalendar Suite 2.1.5 - Local File Inclusion: A directory traversal vulnerability in the GCalendar (com_gcalendar) component 2.1.5 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0972"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0972, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0972.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_gcalendar" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_0982_com_cartweberp {
    meta:
        attack_type = "cve_2010_0982"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_cartweberp - Local File Inclusion: A directory traversal vulnerability in the CARTwebERP (com_cartweberp) component 1.56.75 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-0982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-0982.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_cartweberp" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1056_com_rokdownloads {
    meta:
        attack_type = "cve_2010_1056"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_rokdownloads - Local File Inclusion: A directory traversal vulnerability in the RokDownloads (com_rokdownloads) component before 1.0.1 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1056"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1056, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1056.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_rokdownloads" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1081_com_communitypolls {
    meta:
        attack_type = "cve_2010_1081"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_communitypolls 1.5.2 - Local File Inclusion: A directory traversal vulnerability in the Community Polls (com_communitypolls) component 1.5.2, and possibly earlier, for Core Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1081"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1081, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1081.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_communitypolls" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1217_je_form_creator {
    meta:
        attack_type = "cve_2010_1217"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component & Plugin JE Tooltip 1.0 - Local File Inclusion: A directory traversal vulnerability in the JE Form Creator (com_jeformcr) component for Joomla!, when magic_quotes_gpc is disabled, allows remote attackers to read arbitrary files via directory traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1217"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1217, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1217.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jeformcr" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1302_com_dwgraphs {
    meta:
        attack_type = "cve_2010_1302"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component DW Graph - Local File Inclusion: A directory traversal vulnerability in dwgraphs.php in the DecryptWeb DW Graphs (com_dwgraphs) component 1.0 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1302"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1302, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1302.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_dwgraphs" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1304_com_userstatus {
    meta:
        attack_type = "cve_2010_1304"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component User Status - Local File Inclusion: A directory traversal vulnerability in userstatus.php in the User Status (com_userstatus) component 1.21.16 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1304"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1304, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1304.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_userstatus" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1305_com_jinventory {
    meta:
        attack_type = "cve_2010_1305"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component JInventory 1.23.02 - Local File Inclusion: A directory traversal vulnerability in jinventory.php in the JInventory (com_jinventory) component 1.23.02 and possibly other versions before 1.26.03, a module for Joomla!, allows remote attackers to read arbitrary."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1305.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jinventory" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1306_com_joomlapicasa2 {
    meta:
        attack_type = "cve_2010_1306"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Picasa 2.0 - Local File Inclusion: A directory traversal vulnerability in the Picasa (com_joomlapicasa2) component 2.0 and 2.0.5 for Joomla! allows remote attackers to read arbitrary local files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1306"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1306, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1306.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_joomlapicasa2" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1307_com_joomlaupdater {
    meta:
        attack_type = "cve_2010_1307"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Magic Updater - Local File Inclusion: A directory traversal vulnerability in the Magic Updater (com_joomlaupdater) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1307"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1307, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1307.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_joomlaupdater" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1313_com_sebercart {
    meta:
        attack_type = "cve_2010_1313"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Saber Cart 1.0.0.12 - Local File Inclusion: A directory traversal vulnerability in the Seber Cart (com_sebercart) component 1.0.0.12 and 1.0.0.13 for Joomla!, when magic_quotes_gpc is disabled, allows remote attackers to read arbitrary files via a .. (dot dot)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1313"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1313, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1313.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_sebercart" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1314_com_hsconfig {
    meta:
        attack_type = "cve_2010_1314"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Highslide 1.5 - Local File Inclusion: A directory traversal vulnerability in the Highslide JS (com_hsconfig) component 1.5 and 2.0.9 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1314.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_hsconfig" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1315_com_weberpcustomer {
    meta:
        attack_type = "cve_2010_1315"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component webERPcustomer - Local File Inclusion: A directory traversal vulnerability in weberpcustomer.php in the webERPcustomer (com_weberpcustomer) component 1.2.1 and 1.x before 1.06.02 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1315.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_weberpcustomer" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1340_com_jresearch {
    meta:
        attack_type = "cve_2010_1340"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component com_jresearch - 'Controller' Local File Inclusion: A directory traversal vulnerability in jresearch.php in the J!Research (com_jresearch) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1340"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1340, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1340.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jresearch" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1345_com_ckforms {
    meta:
        attack_type = "cve_2010_1345"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Cookex Agency CKForms - Local File Inclusion: A directory traversal vulnerability in the Cookex Agency CKForms (com_ckforms) component 1.3.3 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1345"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1345, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1345.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_ckforms" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1352_com_jukebox {
    meta:
        attack_type = "cve_2010_1352"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Juke Box 1.7 - Local File Inclusion: A directory traversal vulnerability in the JOOFORGE Jutebox (com_jukebox) component 1.0 and 1.7 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1352"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1352, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1352.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jukebox" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1353_com_loginbox {
    meta:
        attack_type = "cve_2010_1353"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component LoginBox - Local File Inclusion: A directory traversal vulnerability in the LoginBox Pro (com_loginbox) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1353"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1353, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1353.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_loginbox" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1428_jboss_enterprise_application_p {
    meta:
        attack_type = "cve_2010_1428"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Red Hat JBoss - Web/JMX Console Access: Red Hat JBoss Enterprise Application Platform (EAP) can expose the Web Console, JMX Console, and JMXInvokerServlet without authentication, allowing remote attackers to reach admin dashboards and interact with MBeans, leading to full."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1428"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1428, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1428.yaml"
    strings:
        $path0 = "/invoker/JMXInvokerServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_1461_com_photobattle {
    meta:
        attack_type = "cve_2010_1461"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Photo Battle 1.0.1 - Local File Inclusion: A directory traversal vulnerability in the Photo Battle (com_photobattle) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files via the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1461"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1461, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1461.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_photobattle" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1469_com_jprojectmanager {
    meta:
        attack_type = "cve_2010_1469"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component JProject Manager 1.0 - Local File Inclusion: A directory traversal vulnerability in the Ternaria Informatica JProject Manager (com_jprojectmanager) component 1.0 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1469"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1469, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1469.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jprojectmanager" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1471_com_addressbook {
    meta:
        attack_type = "cve_2010_1471"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Address Book 1.5.0 - Local File Inclusion: A directory traversal vulnerability in the AddressBook (com_addressbook) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1471"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1471, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1471.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_addressbook" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1472_com_horoscope {
    meta:
        attack_type = "cve_2010_1472"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Horoscope 1.5.0 - Local File Inclusion: A directory traversal vulnerability in the Daily Horoscope (com_horoscope) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1472"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1472, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1472.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_horoscope" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1473_com_advertising {
    meta:
        attack_type = "cve_2010_1473"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Advertising 0.25 - Local File Inclusion: A directory traversal vulnerability in the Advertising (com_advertising) component 0.25 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1473"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1473, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1473.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_advertising" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1474_com_sweetykeeper {
    meta:
        attack_type = "cve_2010_1474"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Sweetykeeper 1.5 - Local File Inclusion: A directory traversal vulnerability in the Sweety Keeper (com_sweetykeeper) component 1.5.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1474"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1474, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1474.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_sweetykeeper" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1475_com_preventive {
    meta:
        attack_type = "cve_2010_1475"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Preventive And Reservation 1.0.5 - Local File Inclusion: A directory traversal vulnerability in the Preventive & Reservation (com_preventive) component 1.0.5 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1475"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1475, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1475.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_preventive" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1476_com_alphauserpoints {
    meta:
        attack_type = "cve_2010_1476"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component AlphaUserPoints 1.5.5 - Local File Inclusion: A directory traversal vulnerability in the AlphaUserPoints (com_alphauserpoints) component 1.5.5 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1476"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1476, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1476.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_alphauserpoints" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1478_com_jfeedback {
    meta:
        attack_type = "cve_2010_1478"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Jfeedback 1.2 - Local File Inclusion: A directory traversal vulnerability in the Ternaria Informatica Jfeedback! (com_jfeedback) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1478"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1478, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1478.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jfeedback" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1491_com_mmsblog {
    meta:
        attack_type = "cve_2010_1491"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component MMS Blog 2.3.0 - Local File Inclusion: A directory traversal vulnerability in the MMS Blog (com_mmsblog) component 2.3.0 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1491"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1491, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1491.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_mmsblog" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1494_com_awdwall {
    meta:
        attack_type = "cve_2010_1494"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component AWDwall 1.5.4 - Local File Inclusion: A directory traversal vulnerability in the AWDwall (com_awdwall) component 1.5.4 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1494"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1494, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1494.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_awdwall" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1495_com_matamko {
    meta:
        attack_type = "cve_2010_1495"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Matamko 1.01 - Local File Inclusion: A directory traversal vulnerability in the Matamko (com_matamko) component 1.01 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1495"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1495, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1495.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_matamko" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1531_com_redshop {
    meta:
        attack_type = "cve_2010_1531"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component redSHOP 1.0 - Local File Inclusion: A directory traversal vulnerability in the redSHOP (com_redshop) component 1.0.x for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1531"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1531, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1531.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_redshop" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1532_com_powermail {
    meta:
        attack_type = "cve_2010_1532"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component PowerMail Pro 1.5.3 - Local File Inclusion: A directory traversal vulnerability in the givesight PowerMail Pro (com_powermail) component 1.5.3 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1532"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1532, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1532.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_powermail" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1533_com_tweetla {
    meta:
        attack_type = "cve_2010_1533"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component TweetLA 1.0.1 - Local File Inclusion: A directory traversal vulnerability in the TweetLA (com_tweetla) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1533"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1533, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1533.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_tweetla" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1534_com_shoutbox {
    meta:
        attack_type = "cve_2010_1534"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Shoutbox Pro - Local File Inclusion: A directory traversal vulnerability in the Shoutbox Pro (com_shoutbox) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1534"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1534, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1534.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_shoutbox" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1535_com_travelbook {
    meta:
        attack_type = "cve_2010_1535"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component TRAVELbook 1.0.1 - Local File Inclusion: A directory traversal vulnerability in the TRAVELbook (com_travelbook) component 1.0.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1535"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1535, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1535.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_travelbook" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1586_system_management_homepage {
    meta:
        attack_type = "cve_2010_1586"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HP System Management Homepage (SMH) v2.x.x.x - Open Redirect: Open redirect vulnerability in red2301.html in HP System Management Homepage (SMH) 2.x.x.x allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via the RedirectUrl parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1586"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1586, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1586.yaml"
    strings:
        $path0 = "/red2301.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_1601_com_jacomment {
    meta:
        attack_type = "cve_2010_1601"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component JA Comment - Local File Inclusion: A directory traversal vulnerability in the JA Comment (com_jacomment) component for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1601"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1601, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1601.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jacomment" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1602_com_zimbcomment {
    meta:
        attack_type = "cve_2010_1602"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component ZiMB Comment 0.8.1 - Local File Inclusion: A directory traversal vulnerability in the ZiMB Comment (com_zimbcomment) component 0.8.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1602"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1602, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1602.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_zimbcomment" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1603_com_zimbcore {
    meta:
        attack_type = "cve_2010_1603"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component ZiMBCore 0.1 - Local File Inclusion: A directory traversal vulnerability in the ZiMB Core (aka ZiMBCore or com_zimbcore) component 0.1 in the ZiMB Manager collection for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1603"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1603, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1603.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_zimbcore" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1653_com_graphics {
    meta:
        attack_type = "cve_2010_1653"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Graphics 1.0.6 - Local File Inclusion: A directory traversal vulnerability in graphics.php in the Graphics (com_graphics) component 1.0.6 and 1.5.0 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1653"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1653, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1653.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_graphics" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1657_com_smartsite {
    meta:
        attack_type = "cve_2010_1657"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component SmartSite 1.0.0 - Local File Inclusion: A directory traversal vulnerability in the SmartSite (com_smartsite) component 1.0.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1657"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1657, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1657.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_smartsite" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1658_com_noticeboard {
    meta:
        attack_type = "cve_2010_1658"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component NoticeBoard 1.3 - Local File Inclusion: A directory traversal vulnerability in the Code-Garage NoticeBoard (com_noticeboard) component 1.3 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1658"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1658, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1658.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_noticeboard" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1659_com_ultimateportfolio {
    meta:
        attack_type = "cve_2010_1659"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Ultimate Portfolio 1.0 - Local File Inclusion: A directory traversal vulnerability in the Ultimate Portfolio (com_ultimateportfolio) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1659"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1659, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1659.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_ultimateportfolio" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1714_com_arcadegames {
    meta:
        attack_type = "cve_2010_1714"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Arcade Games 1.0 - Local File Inclusion: A directory traversal vulnerability in the Arcade Games (com_arcadegames) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1714"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1714, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1714.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_arcadegames" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1715_com_onlineexam {
    meta:
        attack_type = "cve_2010_1715"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Online Exam 1.5.0 - Local File Inclusion: A directory traversal vulnerability in the Online Examination (aka Online Exam or com_onlineexam) component 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1715"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1715, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1715.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_onlineexam" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1717_if_surfalert {
    meta:
        attack_type = "cve_2010_1717"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component iF surfALERT 1.2 - Local File Inclusion: A directory traversal vulnerability in the iF surfALERT (com_if_surfalert) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1717"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1717, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1717.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_if_surfalert" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1718_com_archeryscores {
    meta:
        attack_type = "cve_2010_1718"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Archery Scores 1.0.6 - Local File Inclusion: A directory traversal vulnerability in archeryscores.php in the Archery Scores (com_archeryscores) component 1.0.6 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1718"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1718, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1718.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_archeryscores" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1719_com_mtfireeagle {
    meta:
        attack_type = "cve_2010_1719"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component MT Fire Eagle 1.2 - Local File Inclusion: A directory traversal vulnerability in the MT Fire Eagle (com_mtfireeagle) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1719"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1719, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1719.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_mtfireeagle" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1723_com_drawroot {
    meta:
        attack_type = "cve_2010_1723"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component iNetLanka Contact Us Draw Root Map 1.1 - Local File Inclusion: A directory traversal vulnerability in the iNetLanka Contact Us Draw Root Map (com_drawroot) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1723"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1723, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1723.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_drawroot" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1858_com_smestorage {
    meta:
        attack_type = "cve_2010_1858"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component SMEStorage - Local File Inclusion: A directory traversal vulnerability in the SMEStorage (com_smestorage) component before 1.1 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1858"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1858, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1858.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_smestorage" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1875_com_properties {
    meta:
        attack_type = "cve_2010_1875"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Property - Local File Inclusion: A directory traversal vulnerability in the Real Estate Property (com_properties) component 3.1.22-03 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1875.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_properties" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1878_com_orgchart {
    meta:
        attack_type = "cve_2010_1878"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component OrgChart 1.0.0 - Local File Inclusion: A directory traversal vulnerability in the OrgChart (com_orgchart) component 1.0.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1878"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1878, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1878.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_orgchart" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1952_com_beeheard {
    meta:
        attack_type = "cve_2010_1952"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component BeeHeard 1.0 - Local File Inclusion: A directory traversal vulnerability in the BeeHeard (com_beeheard) and BeeHeard Lite (com_beeheardlite) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1952.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_beeheard" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1953_com_multimap {
    meta:
        attack_type = "cve_2010_1953"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component iNetLanka Multiple Map 1.0 - Local File Inclusion: A directory traversal vulnerability in the iNetLanka Multiple Map (com_multimap) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1953"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1953, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1953.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_multimap" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1954_com_multiroot {
    meta:
        attack_type = "cve_2010_1954"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component iNetLanka Multiple root 1.0 - Local File Inclusion: A directory traversal vulnerability in the iNetLanka Multiple root (com_multiroot) component 1.0 and 1.1 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1954, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1954.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_multiroot" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1955_com_blogfactory {
    meta:
        attack_type = "cve_2010_1955"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Deluxe Blog Factory 1.1.2 - Local File Inclusion: A directory traversal vulnerability in the Deluxe Blog Factory (com_blogfactory) component 1.1.2 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1955"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1955, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1955.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_blogfactory" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1956_com_gadgetfactory {
    meta:
        attack_type = "cve_2010_1956"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Gadget Factory 1.0.0 - Local File Inclusion: A directory traversal vulnerability in the Gadget Factory (com_gadgetfactory) component 1.0.0 and 1.5.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1956.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_gadgetfactory" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1957_com_lovefactory {
    meta:
        attack_type = "cve_2010_1957"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Love Factory 1.3.4 - Local File Inclusion: A directory traversal vulnerability in the Love Factory (com_lovefactory) component 1.3.4 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1957"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1957, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1957.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_lovefactory" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1979_com_datafeeds {
    meta:
        attack_type = "cve_2010_1979"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Affiliate Datafeeds 880 - Local File Inclusion: A directory traversal vulnerability in the Affiliate Datafeeds (com_datafeeds) component build 880 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1979"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1979, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1979.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_datafeeds" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1980_com_joomlaflickr {
    meta:
        attack_type = "cve_2010_1980"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Joomla! Flickr 1.0 - Local File Inclusion: A directory traversal vulnerability in joomlaflickr.php in the Joomla! Flickr (com_joomlaflickr) component 1.0.3 for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1980"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1980, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1980.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_joomlaflickr" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1982_com_javoice {
    meta:
        attack_type = "cve_2010_1982"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component JA Voice 2.0 - Local File Inclusion: A directory traversal vulnerability in the JA Voice (com_javoice) component 2.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1982.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_javoice" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_1983_com_redtwitter {
    meta:
        attack_type = "cve_2010_1983"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component redTWITTER 1.0 - Local File Inclusion: A drectory traversal vulnerability in the redTWITTER (com_redtwitter) component 1.0.x including 1.0b11 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the view parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-1983"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1983, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-1983.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_redtwitter" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2018_lokomedia_cms {
    meta:
        attack_type = "cve_2010_2018"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lokomedia CMS - Local File Inclusion: A Local File Inclusion (LFI) vulnerability exists in Lokomedia CMS. The application allows an attacker to include files on the server that should not be accessible, potentially exposing sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2018"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2018, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2018.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/downlot.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_2033_com_perchacategoriestree {
    meta:
        attack_type = "cve_2010_2033"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Percha Categories Tree 0.6 - Local File Inclusion: A directory traversal vulnerability in the Percha Fields Attach (com_perchafieldsattach) component 1.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a ..."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2033"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2033, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2033.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_perchacategoriestree" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2034_com_perchaimageattach {
    meta:
        attack_type = "cve_2010_2034"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Percha Image Attach 1.1 - Directory Traversal: A directory traversal vulnerability in the Percha Image Attach (com_perchaimageattach) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a ..."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2034"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2034, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2034.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_perchaimageattach" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2035_com_perchagallery {
    meta:
        attack_type = "cve_2010_2035"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Percha Gallery 1.6 Beta - Directory Traversal: A directory traversal vulnerability in the Percha Gallery (com_perchagallery) component 1.6 Beta for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a ..."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2035"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2035, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2035.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_perchagallery" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2036_com_perchafieldsattach {
    meta:
        attack_type = "cve_2010_2036"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Percha Fields Attach 1.0 - Directory Traversal: A directory traversal vulnerability in the Percha Fields Attach (com_perchafieldsattach) component 1.x for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2036"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2036, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2036.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_perchafieldsattach" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2037_com_perchadownloadsattach {
    meta:
        attack_type = "cve_2010_2037"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Percha Downloads Attach 1.1 - Directory Traversal: A directory traversal vulnerability in the Percha Downloads Attach (com_perchadownloadsattach) component 1.1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2037"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2037, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2037.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_perchadownloadsattach" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2045_com_dioneformwizard {
    meta:
        attack_type = "cve_2010_2045"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component FDione Form Wizard 1.0.2 - Local File Inclusion: A directory traversal vulnerability in the Dione Form Wizard (aka FDione or com_dioneformwizard) component 1.0.2 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2045"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2045, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2045.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_dioneformwizard" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2050_com_mscomment {
    meta:
        attack_type = "cve_2010_2050"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component MS Comment 0.8.0b - Local File Inclusion: A directory traversal vulnerability in the Moron Solutions MS Comment (com_mscomment) component 0.8.0b for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2050"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2050, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2050.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_mscomment" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2122_com_simpledownload {
    meta:
        attack_type = "cve_2010_2122"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component simpledownload <=0.9.5 - Arbitrary File Retrieval: A directory traversal vulnerability in the SimpleDownload (com_simpledownload) component before 0.9.6 for Joomla! allows remote attackers to retrieve arbitrary files via a .. (dot dot) in the controller."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2122"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2122, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2122.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_simpledownload" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2128_com_jequoteform {
    meta:
        attack_type = "cve_2010_2128"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component JE Quotation Form 1.0b1 - Local File Inclusion: A directory traversal vulnerability in the JE Quotation Form (com_jequoteform) component 1.0b1 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2128"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2128, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2128.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jequoteform" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2259_com_bfsurvey_profree {
    meta:
        attack_type = "cve_2010_2259"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component com_bfsurvey - Local File Inclusion: A directory traversal vulnerability in the BF Survey (com_bfsurvey) component for Joomla! allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the controller parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2259"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2259, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2259.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_bfsurvey" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2507_com_picasa2gallery {
    meta:
        attack_type = "cve_2010_2507"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Picasa2Gallery 1.2.8 - Local File Inclusion: A directory traversal vulnerability in the Picasa2Gallery (com_picasa2gallery) component 1.2.8 and earlier for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2507"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2507, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2507.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_picasa2gallery" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2680_com_jesectionfinder {
    meta:
        attack_type = "cve_2010_2680"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component jesectionfinder - Local File Inclusion: A directory traversal vulnerability in the JExtensions JE Section/Property Finder (jesectionfinder) component for Joomla! allows remote attackers to include and execute arbitrary local files via directory traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2680"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2680, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2680.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/propertyfinder/component/jesectionfinder/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_2682_com_realtyna {
    meta:
        attack_type = "cve_2010_2682"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Realtyna Translator 1.0.15 - Local File Inclusion: A directory traversal vulnerability in the Realtyna Translator (com_realtyna) component 1.0.15 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a ..."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2682"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2682, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2682.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_realtyna" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2857_com_music {
    meta:
        attack_type = "cve_2010_2857"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Music Manager - Local File Inclusion: A directory traversal vulnerability in the Music Manager component for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impacts via a .. (dot dot) in the cid parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2857"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2857, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2857.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/component/music/album.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_2861_coldfusion {
    meta:
        attack_type = "cve_2010_2861"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Adobe ColdFusion 8.0/8.0.1/9.0/9.0.1 LFI: Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter to (1) CFIDE/administrator/settings/mappings.cfm."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2861"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2861, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2861.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/CFIDE/administrator/enter.cfm" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_2918_com_joomla_visites {
    meta:
        attack_type = "cve_2010_2918"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Visites 1.1 - MosConfig_absolute_path Remote File Inclusion: A PHP remote file inclusion vulnerability in core/include/myMailer.class.php in the Visites (com_joomla-visites) component 1.1 RC2 for Joomla! allows remote attackers to execute arbitrary PHP code."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2918"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2918, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2918.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/administrator/components/com_joomla-visites/core/include/myMailer.class.php" ascii nocase
        $param0 = "mosConfig_absolute_path=../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_2920_com_foobla_suggestions {
    meta:
        attack_type = "cve_2010_2920"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component Foobla Suggestions 1.5.1.2 - Local File Inclusion: A directory traversal vulnerability in the Foobla Suggestions (com_foobla_suggestions) component 1.5.1.2 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-2920"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2920, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-2920.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_foobla_suggestions" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_3203_com_picsell {
    meta:
        attack_type = "cve_2010_3203"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component PicSell 1.0 - Arbitrary File Retrieval: A directory traversal vulnerability in the PicSell (com_picsell) component 1.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the dflink parameter in a prevsell dwnfree action to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-3203"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-3203, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-3203.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_picsell" ascii nocase
        $param1 = "controller=prevsell" ascii nocase
        $param2 = "task=dwnfree" ascii nocase
        $param3 = "dflink=../../../configuration.php" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_4239_tikiwiki_cms_groupware {
    meta:
        attack_type = "cve_2010_4239"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tiki Wiki CMS Groupware 5.2 - Local File Inclusion: Tiki Wiki CMS Groupware 5.2 is susceptible to a local file inclusion vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-4239"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-4239, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-4239.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/tiki-jsplugin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2010_4617_com_jotloader {
    meta:
        attack_type = "cve_2010_4617"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla! Component JotLoader 2.2.1 - Local File Inclusion: A directory traversal vulnerability in the JotLoader (com_jotloader) component 2.2.1 for Joomla! allows remote attackers to read arbitrary files via directory traversal sequences in the section parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-4617"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-4617, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-4617.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jotloader" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_4769_com_jimtawl {
    meta:
        attack_type = "cve_2010_4769"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Jimtawl 1.0.2 - Local File Inclusion: A directory traversal vulnerability in the Jimtawl (com_jimtawl) component 1.0.2 Joomla! allows remote attackers to read arbitrary files and possibly unspecified other impacts via a .. (dot dot) in the task parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-4769"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-4769, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-4769.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_jimtawl" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_4977_com_canteen {
    meta:
        attack_type = "cve_2010_4977"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Canteen 1.0 - Local File Inclusion: A SQL injection vulnerability in menu.php in the Canteen (com_canteen) component 1.0 for Joomla! allows remote attackers to execute arbitrary SQL commands via the mealid parameter to index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-4977"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-4977, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-4977.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_canteen" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2010_5278_modx_revolution {
    meta:
        attack_type = "cve_2010_5278"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MODx manager - Local File Inclusion: A directory traversal vulnerability in manager/controllers/default/resource/tvs.php in MODx Revolution 2.0.2-pl and possibly earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the class_key parameter when."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2010-5278"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-5278, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2010/CVE-2010-5278.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/manager/controllers/default/resource/tvs.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_0049_majordomo_2 {
    meta:
        attack_type = "cve_2011_0049"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Majordomo2 - SMTP/HTTP Directory Traversal: A directory traversal vulnerability in the _list_file_get function in lib/Majordomo.pm in Majordomo 2 before 20110131 allows remote attackers to read arbitrary files via .. (dot dot) sequences in the help command, as demonstrated."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-0049"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0049, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-0049.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgi-bin/mj_wwwusr" ascii nocase
        $param0 = "extra=/../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2011_1669_wp_custom_pages {
    meta:
        attack_type = "cve_2011_1669"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Custom Pages 0.5.0.1 - Local File Inclusion (LFI): A directory traversal vulnerability in wp-download.php in the WP Custom Pages module 0.5.0.1 for WordPress allows remote attackers to read arbitrary files via ..%2F (encoded dot dot) sequences in the url parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-1669"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-1669, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-1669.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/wp-custom-pages/wp-download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_3315_unified_ip_interactive_voice_r {
    meta:
        attack_type = "cve_2011_3315"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco CUCM, UCCX, and Unified IP-IVR- Directory Traversal: A directory traversal vulnerability in Cisco Unified Communications Manager (CUCM) 5.x and 6.x before 6.1(5)SU2, 7.x before 7.1(5b)SU2, and 8.x before 8.0(3), and Cisco Unified Contact Center Express (aka Unified CCX or."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-3315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-3315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-3315.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/ccmivr/IVRGetAudioFile.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_4336_tikiwiki_cms_groupware {
    meta:
        attack_type = "cve_2011_4336"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tiki Wiki CMS Groupware 7.0 Cross-Site Scripting: Tiki Wiki CMS Groupware 7.0 is vulnerable to cross-site scripting via the GET 'ajax' parameter to snarf_ajax.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-4336"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-4336, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-4336.yaml"
        response_type = "xss"
    strings:
        $path0 = "/snarf_ajax.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_4618_advanced_text_widget_plugin {
    meta:
        attack_type = "cve_2011_4618"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Advanced Text Widget < 2.0.2 - Cross-Site Scripting: A cross-site scripting (XSS) vulnerability in advancedtext.php in Advanced Text Widget plugin before 2.0.2 for WordPress allows remote attackers to inject arbitrary web script or HTML via the page parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-4618"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-4618, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-4618.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/advanced-text-widget/advancedtext.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_4624_grand_flagallery {
    meta:
        attack_type = "cve_2011_4624"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GRAND FlAGallery 1.57 - Cross-Site Scripting: A cross-site scripting (XSS) vulnerability in facebook.php in the GRAND FlAGallery plugin (flash-album-gallery) before 1.57 for WordPress allows remote attackers to inject arbitrary web script or HTML via the i parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-4624"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-4624, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-4624.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/flash-album-gallery/facebook.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_4640_webtitan {
    meta:
        attack_type = "cve_2011_4640"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WebTitan < 3.60 - Local File Inclusion: Directory traversal vulnerability in logs-x.php in SpamTitan WebTitan before 3.60 allows remote authenticated users to read arbitrary files via a .. (dot dot) in the fname parameter in a view action."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-4640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-4640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-4640.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "fname=../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2011_4926_adminimize {
    meta:
        attack_type = "cve_2011_4926"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adminimize 1.7.22 - Cross-Site Scripting: A cross-site scripting vulnerability in adminimize/adminimize_page.php in the Adminimize plugin before 1.7.22 for WordPress allows remote attackers to inject arbitrary web script or HTML via the page parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-4926"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-4926, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-4926.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/adminimize/adminimize_page.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5106_flexible_custom_post_type {
    meta:
        attack_type = "cve_2011_5106"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Flexible Custom Post Type < 0.1.7 - Cross-Site Scripting: A cross-site scripting vulnerability in edit-post.php in the Flexible Custom Post Type plugin before 0.1.7 for WordPress allows remote attackers to inject arbitrary web script or HTML via the id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5106"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5106, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5106.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/flexible-custom-post-type/edit-post.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5107_alert_before_you_post {
    meta:
        attack_type = "cve_2011_5107"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Alert Before Your Post <= 0.1.1 - Cross-Site Scripting: A cross-site scripting vulnerability in post_alert.php in Alert Before Your Post plugin, possibly 0.1.1 and earlier, for WordPress allows remote attackers to inject arbitrary web script or HTML via the name parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5107, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5107.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/alert-before-your-post/trunk/post_alert.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5179_skysa_app_bar_integration_plug {
    meta:
        attack_type = "cve_2011_5179"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Skysa App Bar 1.04 - Cross-Site Scripting: A cross-site scripting vulnerability in skysa-official/skysa.php in Skysa App Bar Integration plugin, possibly before 1.04, for WordPress allows remote attackers to inject arbitrary web script or HTML via the submit parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5179"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5179, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5179.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/skysa-official/skysa.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5181_clickdesk_live_support_live_ch {
    meta:
        attack_type = "cve_2011_5181"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ClickDesk Live Support Live Chat 2.0 - Cross-Site Scripting: A cross-site scripting vulnerability in clickdesk.php in ClickDesk Live Support - Live Chat plugin 2.0 for WordPress allows remote attackers to inject arbitrary web script or HTML via the cdwidgetid parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5181"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5181, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5181.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/clickdesk-live-support-chat/clickdesk.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5252_orchard {
    meta:
        attack_type = "cve_2011_5252"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Orchard 'ReturnUrl' Parameter URI - Open Redirect: Open redirect vulnerability in Users/Account/LogOff in Orchard 1.0.x before 1.0.21, 1.1.x before 1.1.31, 1.2.x before 1.2.42, and 1.3.x before 1.3.10 allows remote attackers to redirect users to arbitrary web sites and conduct."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5252"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5252, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5252.yaml"
    strings:
        $path0 = "/orchard/Users/Account/LogOff" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2011_5265_featurific_for_wordpress {
    meta:
        attack_type = "cve_2011_5265"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Featurific For WordPress 1.6.2 - Cross-Site Scripting: A cross-site scripting vulnerability in cached_image.php in the Featurific For WordPress plugin 1.6.2 for WordPress allows remote attackers to inject arbitrary web script or HTML via the snum parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2011-5265"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-5265, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2011/CVE-2011-5265.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/featurific-for-wordpress/cached_image.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_0392_struts {
    meta:
        attack_type = "cve_2012_0392"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Struts2 S2-008 RCE: The CookieInterceptor component in Apache Struts before 2.3.1.1 does not use the parameter-name whitelist, which allows remote attackers to execute arbitrary commands via a crafted HTTP Cookie header that triggers Java code execution through a static."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-0392"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0392, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-0392.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/devmode.action" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_0394_struts {
    meta:
        attack_type = "cve_2012_0394"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Struts <2.3.1.1 - Remote Code Execution: Apache Struts before 2.3.1.1 is susceptible to remote code execution. When developer mode is used in the DebuggingInterceptor component, a remote attacker can execute arbitrary OGNL commands via unspecified vectors, which can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-0394"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0394, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-0394.yaml"
    strings:
        $path0 = "/portal/displayAPSForm.action" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_0896_count_per_day {
    meta:
        attack_type = "cve_2012_0896"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Count Per Day <= 3.1 - download.php f Parameter Traversal Arbitrary File Access: An absolute path traversal vulnerability in download.php in the Count Per Day module before 3.1.1 for WordPress allows remote attackers to read arbitrary files via the f parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-0896"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0896, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-0896.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/count-per-day/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_0901_yousaytoo {
    meta:
        attack_type = "cve_2012_0901"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "YouSayToo auto-publishing 1.0 - Cross-Site Scripting: A cross-site scripting vulnerability in yousaytoo.php in YouSayToo auto-publishing plugin 1.0 for WordPress allows remote attackers to inject arbitrary web script or HTML via the submit parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-0901"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0901, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-0901.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/yousaytoo-auto-publishing-plugin/yousaytoo.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_0991_openemr {
    meta:
        attack_type = "cve_2012_0991"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "OpenEMR 4.1 - Local File Inclusion: Multiple directory traversal vulnerabilities in OpenEMR 4.1.0 allow remote authenticated users to read arbitrary files via a .. (dot dot) in the formname parameter to (1) contrib/acog/print_form.php; or (2) load_form.php, (3) view_form.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-0991"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0991, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-0991.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/contrib/acog/print_form.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_10018_mapplic {
    meta:
        attack_type = "cve_2012_10018"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Mapplic <= 6.1 / Mapplic Lite <= 1.0 - Authenticated Stored XSS via SVG File Upload: The Mapplic and Mapplic Lite plugins for WordPress are vulnerable to Stored Cross-Site Scripting via arbitrary URL injection in versions up to and including 6.1 and 1.0 respectively.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-10018"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-10018, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-10018.yaml"
        response_type = "xss"
    strings:
        $param0 = "post_type=mapplic_map" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_1226_dolibarr_erp_crm {
    meta:
        attack_type = "cve_2012_1226"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dolibarr ERP/CRM 3.2 Alpha - Multiple Directory Traversal Vulnerabilities: Multiple directory traversal vulnerabilities in Dolibarr CMS 3.2.0 Alpha allow remote attackers to read arbitrary files and possibly execute arbitrary code via a .. (dot dot) in the (1) file parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-1226"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1226, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-1226.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "modulepart=project" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_1835_all_in_one_event_calendar {
    meta:
        attack_type = "cve_2012_1835"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin All-in-One Event Calendar 1.4 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in the All-in-One Event Calendar plugin 1.4 and 1.5 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) title parameter to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-1835"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1835, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-1835.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/all-in-one-event-calendar/app/view/agenda-widget.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_3153_fusion_middleware {
    meta:
        attack_type = "cve_2012_3153"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Forms & Reports RCE (CVE-2012-3152 & CVE-2012-3153): An unspecified vulnerability in the Oracle Reports Developer component in Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0 allows remote attackers to affect confidentiality and integrity via unknown vectors."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-3153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-3153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-3153.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/reports/rwservlet/showenv" ascii nocase
        $path1 = "/reports/rwservlet" ascii nocase
        $param0 = "destype=cache" ascii nocase
        $param1 = "JOBTYPE=rwurl" ascii nocase
        $param2 = "URLPARAMETER=file:///" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_4032_websitepanel {
    meta:
        attack_type = "cve_2012_4032"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WebsitePanel before v1.2.2.1 - Open Redirect: Open redirect vulnerability in the login page in WebsitePanel before 1.2.2.1 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in ReturnUrl to Default.aspx"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4032"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4032, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4032.yaml"
    strings:
        $param0 = "ctl03$ctl01$ctl00$ddlLanguage=en-US" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_4253_mysqldumper {
    meta:
        attack_type = "cve_2012_4253"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MySQLDumper 1.24.4 - Directory Traversal: Multiple directory traversal vulnerabilities in MySQLDumper 1.24.4 allow remote attackers to read arbitrary files via a .. (dot dot) in the (1) language parameter to learn/cubemail/install.php or (2) f parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4253"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4253, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4253.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/learn/cubemail/filemanagement.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_4273_2_click_social_media_buttons {
    meta:
        attack_type = "cve_2012_4273"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "2 Click Socialmedia Buttons < 0.34 - Cross-Site Scripting: A cross-site scripting vulnerability in libs/xing.php in the 2 Click Social Media Buttons plugin before 0.34 for WordPress allows remote attackers to inject arbitrary web script or HTML via the xing-url parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4273"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4273, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4273.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/2-click-socialmedia-buttons/libs/xing.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_4878_flatnux {
    meta:
        attack_type = "cve_2012_4878"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FlatnuX CMS - Directory Traversal: A path traversal vulnerability in controlcenter.php in FlatnuX CMS 2011 08.09.2 allows remote administrators to read arbitrary files via a full pathname in the dir parameter in a contents/Files action."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4878"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4878, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4878.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/controlcenter.php" ascii nocase
        $param0 = "ffile=passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_4889_firewall_analyzer {
    meta:
        attack_type = "cve_2012_4889"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ManageEngine Firewall Analyzer 7.2 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in ManageEngine Firewall Analyzer 7.2 allow remote attackers to inject arbitrary web script or HTML via the (1) subTab or (2) tab parameter to createAnomaly.do; (3) url, (4)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4889"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4889, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4889.yaml"
        response_type = "xss"
    strings:
        $path0 = "/fw/syslogViewer.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_4940_axigen_free_mail_server {
    meta:
        attack_type = "cve_2012_4940"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Axigen Mail Server Filename Directory Traversal: Multiple directory traversal vulnerabilities in the View Log Files component in Axigen Free Mail Server allow remote attackers to read or delete arbitrary files via a .. (dot dot) in the fileName parameter in a download action to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-4940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-4940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-4940.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/source/loggin/page_log_dwn_file.hsp" ascii nocase
        $param0 = "h=44ea8a6603cbf54e245f37b4ddaf8f36" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2012_5321_tikiwiki_cms_groupware {
    meta:
        attack_type = "cve_2012_5321"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TikiWiki CMS Groupware v8.3 - Open Redirect: tiki-featured_link.php in TikiWiki CMS/Groupware 8.3 allows remote attackers to load arbitrary web site pages into frames and conduct phishing attacks via the url parameter, aka 'frame injection"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-5321"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-5321, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-5321.yaml"
    strings:
        $path0 = "/tiki-featured_link.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2012_6499_age_verification {
    meta:
        attack_type = "cve_2012_6499"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Age Verification v0.4 - Open Redirect: Open redirect vulnerability in age-verification.php in the Age Verification plugin 0.4 and earlier for WordPress allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2012-6499"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-6499, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2012/CVE-2012-6499.yaml"
    strings:
        $path0 = "/wp-content/plugins/age-verification/age-verification.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_2287_uploader {
    meta:
        attack_type = "cve_2013_2287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Uploader 1.0.4 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in views/notify.php in the Uploader plugin 1.0.4 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) notify or (2) blog parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-2287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-2287.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/uploader/views/notify.php" ascii nocase
        $param0 = "notify=unnotif" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2013_2621_telaen {
    meta:
        attack_type = "cve_2013_2621"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Telaen => v1.3.1 - Open Redirect: Open Redirection Vulnerability in the redir.php script in Telaen before 1.3.1 allows remote attackers to redirect victims to arbitrary websites via a crafted URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-2621"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2621, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-2621.yaml"
    strings:
        $path0 = "/telaen/redir.php" ascii nocase
        $path1 = "/redir.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_3526_trafficanalyzer {
    meta:
        attack_type = "cve_2013_3526"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Traffic Analyzer - 'aoid' Cross-Site Scripting: A cross-site scripting vulnerability in js/ta_loaded.js.php in the Traffic Analyzer plugin, possibly 3.3.2 and earlier, for WordPress allows remote attackers to inject arbitrary web script or HTML via the aoid."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-3526"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-3526, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-3526.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_4117_category_grid_view_gallery {
    meta:
        attack_type = "cve_2013_4117"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Category Grid View Gallery 2.3.1 - Cross-Site Scripting: A cross-site scripting vulnerability in includes/CatGridPost.php in the Category Grid View Gallery plugin 2.3.1 for WordPress allows remote attackers to inject arbitrary web script or HTML via the ID."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-4117"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-4117, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-4117.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/category-grid-view-gallery/includes/CatGridPost.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_4625_duplicator {
    meta:
        attack_type = "cve_2013_4625"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Duplicator < 0.4.5 - Cross-Site Scripting: A cross-site scripting vulnerability in files/installer.cleanup.php in the Duplicator plugin before 0.4.5 for WordPress allows remote attackers to inject arbitrary web script or HTML via the package parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-4625"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-4625, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-4625.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/duplicator/files/installer.cleanup.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_4982_avtech_dvr {
    meta:
        attack_type = "cve_2013_4982"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "AVTECH DVR - Login Verification Code Bypass: AVTECH DVR products are vulnerable to verification code bypass just by entering the 'login=quick' parameter to bypass verification code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-4982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-4982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-4982.yaml"
    strings:
        $path0 = "/cgi-bin/nobody/VerifyCode.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_5528_unified_communications_manager {
    meta:
        attack_type = "cve_2013_5528"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cisco Unified Communications Manager 7/8/9 - Directory Traversal: A directory traversal vulnerability in the Tomcat administrative web interface in Cisco Unified Communications Manager allows remote authenticated users to read arbitrary files via directory traversal sequences."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-5528"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-5528, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-5528.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/ccmadmin/bulkvivewfilecontents.do" ascii nocase
        $param0 = "filetype=samplefile" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2013_6281_dhtmlxspreadsheet {
    meta:
        attack_type = "cve_2013_6281"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Spreadsheet - Cross-Site Scripting: WordPress Spreadsheet plugin contains a reflected cross-site scripting vulnerability in /dhtmlxspreadsheet/codebase/spreadsheet.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-6281"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-6281, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-6281.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/dhtmlxspreadsheet/codebase/spreadsheet.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_7091_zimbra_collaboration_suite {
    meta:
        attack_type = "cve_2013_7091"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zimbra Collaboration Server 7.2.2/8.0.2 Local File Inclusion: A directory traversal vulnerability in /res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz in Zimbra 7.2.2 and 8.0.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-7091"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-7091, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-7091.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx TemplateMsg.js.zgz" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2013_7240_advanced_dewplayer {
    meta:
        attack_type = "cve_2013_7240"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Advanced Dewplayer 1.2 - Directory Traversal: A directory traversal vulnerability in download-file.php in the Advanced Dewplayer plugin 1.2 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the dew_file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2013-7240"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-7240, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2013/CVE-2013-7240.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/advanced-dewplayer/admin-panel/download-file.php" ascii nocase
        $param0 = "dew_file=../../../../wp-config.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_100004_sitecore_net {
    meta:
        attack_type = "cve_2014_100004"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sitecore CMS - Cross-Site Scripting: Sitecore CMS contains a cross-site scripting vulnerability via the 'special way' of displaying XML Controls directly, which allows for a Cross Site Scripting Attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-100004"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-100004, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-100004.yaml"
        response_type = "xss"
    strings:
        $param0 = "xmlcontrol=body onload=alert(document.domain)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_10037_domphp {
    meta:
        attack_type = "cve_2014_10037"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DomPHP 0.83 - Directory Traversal: A directory traversal vulnerability in DomPHP 0.83 and earlier allows remote attackers to have unspecified impacts via a .. (dot dot) in the url parameter to photoalbum/index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-10037"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-10037, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-10037.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/photoalbum/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_2321_f460 {
    meta:
        attack_type = "cve_2014_2321"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZTE Cable Modem Web Shell: ZTE F460 and F660 cable modems allows remote attackers to obtain administrative access via sendcmd requests to web_shell_cmd.gch, as demonstrated by using 'set TelnetCfg' commands to enable a TELNET service with specified credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-2321"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-2321, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-2321.yaml"
    strings:
        $path0 = "/web_shell_cmd.gch" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_2908_simatic_s7_cpu_1200_firmware {
    meta:
        attack_type = "cve_2014_2908"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Siemens SIMATIC S7-1200 CPU - Cross-Site Scripting: A cross-site scripting vulnerability in the integrated web server on Siemens SIMATIC S7-1200 CPU devices 2.x and 3.x allows remote attackers to inject arbitrary web script or HTML via unspecified vectors."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-2908"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-2908, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-2908.yaml"
        response_type = "xss"
    strings:
        $param0 = "filtername=Name" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_2962_n150_f9k1009_firmware {
    meta:
        attack_type = "cve_2014_2962"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Belkin N150 Router 1.00.08/1.00.09 - Path Traversal: A path traversal vulnerability in the webproc cgi module on the Belkin N150 F9K1009 v1 router with firmware before 1.00.08 allows remote attackers to read arbitrary files via a full pathname in the getpage parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-2962"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-2962, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-2962.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "var:page=deviceinfo" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_3206_blackarmor_nas_220_firmware {
    meta:
        attack_type = "cve_2014_3206"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Seagate BlackArmor NAS - Command Injection: Seagate BlackArmor NAS allows remote attackers to execute arbitrary code via the session parameter to localhost/backupmgt/localJob.php or the auth_name parameter to localhost/backupmgmt/pre_connect_check.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-3206"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-3206, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-3206.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/backupmgt/localJob.php" ascii nocase
        $path1 = "/backupmgt/pre_connect_check.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_3704_drupal {
    meta:
        attack_type = "cve_2014_3704"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Drupal SQL Injection: The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing specially crafted keys."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-3704"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-3704, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-3704.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "form_id=user_login_block" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_4210_fusion_middleware {
    meta:
        attack_type = "cve_2014_4210"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Weblogic - Server-Side Request Forgery: An unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4210"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4210, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4210.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/uddiexplorer/SearchPublicRegistries.jsp" ascii nocase
        $param0 = "rdoSearch=name" ascii nocase
        $param1 = "selfor=Business location" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_4513_activehelper_livehelp_live_cha {
    meta:
        attack_type = "cve_2014_4513"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ActiveHelper LiveHelp Server 3.1.0 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in server/offline.php in the ActiveHelper LiveHelp Live Chat plugin 3.1.0 and earlier for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4513"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4513, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4513.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/activehelper-livehelp/server/offline.php" ascii nocase
        $param0 = "DOMAINID=DOMAINID" ascii nocase
        $param1 = "COMPLETE=COMPLETE" ascii nocase
        $param2 = "COMPANY=COMPANY" ascii nocase
        $param3 = "SECURITY=SECURITY" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_4535_import_legacy_media {
    meta:
        attack_type = "cve_2014_4535"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Import Legacy Media <= 0.1 - Cross-Site Scripting: A cross-site scripting vulnerability in the Import Legacy Media plugin 0.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the filename parameter to getid3/demos/demo.mimeonly.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4535"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4535, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4535.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/import-legacy-media/getid3/demos/demo.mimeonly.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4536_infusionsoft_gravity_forms {
    meta:
        attack_type = "cve_2014_4536"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Infusionsoft Gravity Forms Add-on < 1.5.7 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in tests/notAuto_test_ContactService_pauseCampaign.php in the Infusionsoft Gravity Forms plugin before 1.5.6 for WordPress allow remote attackers to inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4536"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4536, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4536.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/infusionsoft/Infusionsoft/tests/notAuto_test_ContactService_pauseCampaign.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4539_movies {
    meta:
        attack_type = "cve_2014_4539"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Movies <= 0.6 - Cross-Site Scripting: A cross-site scripting vulnerability in the Movies plugin 0.6 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the filename parameter to getid3/demos/demo.mimeonly.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4539"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4539, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4539.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/movies/getid3/demos/demo.mimeonly.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4544_podcast_channels {
    meta:
        attack_type = "cve_2014_4544"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Podcast Channels < 0.28 - Cross-Site Scripting: The Podcast Channels WordPress plugin was affected by an unauthenticated reflected cross-site scripting security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4544"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4544, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4544.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/podcast-channels/getid3/demos/demo.write.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4550_ninja {
    meta:
        attack_type = "cve_2014_4550"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Shortcode Ninja <= 1.4 - Cross-Site Scripting: A cross-site scripting vulnerability in preview-shortcode-external.php in the Shortcode Ninja plugin 1.4 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the shortcode parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4550"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4550, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4550.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/shortcode-ninja/preview-shortcode-external.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4558_swipehq_payment_gateway_woocom {
    meta:
        attack_type = "cve_2014_4558"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WooCommerce Swipe <= 2.7.1 - Cross-Site Scripting: A cross-site scripting vulnerability in test-plugin.php in the Swipe Checkout for WooCommerce plugin 2.7.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the api_url parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4558"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4558, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4558.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/swipehq-payment-gateway-woocommerce/test-plugin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4561_ultimate_weather {
    meta:
        attack_type = "cve_2014_4561"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ultimate Weather Plugin <= 1.0 - Cross-Site Scripting: The ultimate-weather plugin 1.0 for WordPress contains a cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4561"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4561, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4561.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/ultimate-weather-plugin/magpierss/scripts/magpie_debug.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4577_wp_amasin_the_amazon_affiliate {
    meta:
        attack_type = "cve_2014_4577"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP AmASIN The Amazon Affiliate Shop - Local File Inclusion: Absolute path traversal vulnerability in reviews.php in the WP AmASIN - The Amazon Affiliate Shop plugin 0.9.6 and earlier for WordPress allows remote attackers to read arbitrary files via a full pathname in the url."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4577"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4577, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4577.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/wp-amasin-the-amazon-affiliate-shop/reviews.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4592_wp_planet {
    meta:
        attack_type = "cve_2014_4592"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Planet <= 0.1 - Cross-Site Scripting: A cross-site scripting vulnerability in rss.class/scripts/magpie_debug.php in the WP-Planet plugin 0.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the url parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4592"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4592, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4592.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wp-planet/rss.class/scripts/magpie_debug.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4940_tera_charts {
    meta:
        attack_type = "cve_2014_4940"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin Tera Charts - Local File Inclusion: Multiple local file inclusion vulnerabilities in Tera Charts (tera-charts) plugin 0.1 for WordPress allow remote attackers to read arbitrary files via a .. (dot dot) in the fn parameter to (1) charts/treemap.php or (2)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4940.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/tera-charts/charts/zoomabletreemap.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4941_wp_cross_rss {
    meta:
        attack_type = "cve_2014_4941"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cross RSS 1.7 - Local File Inclusion: Absolute path traversal vulnerability in Cross-RSS (wp-cross-rss) plugin 1.7 for WordPress allows remote attackers to read arbitrary files via a full pathname in the rss parameter to proxy.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4941"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4941, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4941.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/cross-rss/proxy.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_4942_wp_easycart {
    meta:
        attack_type = "cve_2014_4942"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress EasyCart <2.0.6 - Information Disclosure: WordPress EasyCart plugin before 2.0.6 contains an information disclosure vulnerability. An attacker can obtain configuration information via a direct request to inc/admin/phpinfo.php, which calls the phpinfo function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-4942"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-4942, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-4942.yaml"
    strings:
        $path0 = "/wp-content/plugins/wp-easycart/inc/admin/phpinfo.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_5111_trixbox {
    meta:
        attack_type = "cve_2014_5111"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Fonality trixbox - Local File Inclusion: Multiple local file inclusion vulnerabilities in Fonality trixbox allow remote attackers to read arbitrary files via a .. (dot dot) in the lang parameter to (1) home/index.php, (2) asterisk_info/asterisk_info.php, (3) repo/repo.php, or."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-5111"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-5111, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-5111.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/maint/modules/endpointcfg/endpointcfg.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_5181_lastfm_rotation_plugin {
    meta:
        attack_type = "cve_2014_5181"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Last.fm Rotation 1.0 - Path Traversal: Directory traversal vulnerability in lastfm-proxy.php in the Last.fm Rotation (lastfm-rotation) plugin 1.0 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the snode parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-5181"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-5181, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-5181.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/lastfm-rotation/lastfm-proxy.php" ascii nocase
        $param0 = "snode=/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_5258_webedition_cms {
    meta:
        attack_type = "cve_2014_5258"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "webEdition 6.3.8.0 - Directory Traversal: A directory traversal vulnerability in showTempFile.php in webEdition CMS before 6.3.9.0 Beta allows remote authenticated users to read arbitrary files via a .. (dot dot) in the file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-5258"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-5258, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-5258.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/webEdition/showTempFile.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_5368_wp_content_source_control {
    meta:
        attack_type = "cve_2014_5368"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin WP Content Source Control - Directory Traversal: A directory traversal vulnerability in the file_get_contents function in downloadfiles/download.php in the WP Content Source Control (wp-source-control) plugin 3.0.0 and earlier for WordPress allows remote."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-5368"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-5368, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-5368.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/wp-source-control/downloadfiles/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_6308_osclass {
    meta:
        attack_type = "cve_2014_6308"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Osclass Security Advisory 3.4.1 - Local File Inclusion: A directory traversal vulnerability in OSClass before 3.4.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter in a render action to oc-admin/index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-6308"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6308, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-6308.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/osclass/oc-admin/index.php" ascii nocase
        $param0 = "page=appearance" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_8676_soplanning {
    meta:
        attack_type = "cve_2014_8676"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Simple Online Planning Tool <1.3.2 - Local File Inclusion: SOPlanning <1.32 contain a directory traversal in the file_get_contents function via a .. (dot dot) in the fichier parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-8676"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8676, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-8676.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/process/feries.php" ascii nocase
        $param0 = "fichier=../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_8739_creative_contact_form {
    meta:
        attack_type = "cve_2014_8739"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Sexy Contact Form (<= 0.9.7) - Arbitrary File Upload: Unrestricted file upload vulnerability in server/php/UploadHandler.php in the jQuery File Upload Plugin 6.4.4 for jQuery, as used in the Creative Solutions Creative Contact Form (formerly Sexy Contact Form) before."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-8739"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8739, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-8739.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php" ascii nocase
        $path1 = "/wp-content/plugins/sexy-contact-form/includes/fileupload/files/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_8799_dukapress {
    meta:
        attack_type = "cve_2014_8799"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin DukaPress 2.5.2 - Directory Traversal: A directory traversal vulnerability in the dp_img_resize function in php/dp-functions.php in the DukaPress plugin before 2.5.4 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the src."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-8799"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8799, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-8799.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/dukapress/lib/dp_image.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_9094_video_gallery {
    meta:
        attack_type = "cve_2014_9094"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress DZS-VideoGallery Plugin Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in deploy/designer/preview.php in the Digital Zoom Studio (DZS) Video Gallery plugin for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9094"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9094, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9094.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/dzs-videogallery/readme" ascii nocase
        $path1 = "/wp-content/plugins/dzs-videogallery/deploy/designer/preview.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_9606_netsweeper {
    meta:
        attack_type = "cve_2014_9606"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Netsweeper 4.0.8 - Cross-Site Scripting: Multiple cross-site scripting vulnerabilities in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allow remote attackers to inject arbitrary web script or HTML via the (1) server parameter to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9606"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9606, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9606.yaml"
        response_type = "xss"
    strings:
        $path0 = "/webadmin/policy/category_table_ajax.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2014_9614_netsweeper {
    meta:
        attack_type = "cve_2014_9614"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Netsweeper 4.0.5 - Default Weak Account: The Web Panel in Netsweeper before 4.0.5 has a default password of 'branding' for the branding account, which makes it easier for remote attackers to obtain access via a request to webadmin/."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9614"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9614, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9614.yaml"
        response_type = "xss"
    strings:
        $path0 = "/webadmin/auth/verification.php" ascii nocase
        $param0 = "login=branding" ascii nocase
        $param1 = "password=branding" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_9615_netsweeper {
    meta:
        attack_type = "cve_2014_9615"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Netsweeper 4.0.4 - Cross-Site Scripting: A cross-site scripting vulnerability in Netsweeper 4.0.4 allows remote attackers to inject arbitrary web script or HTML via the url parameter to webadmin/deny/index.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9615"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9615, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9615.yaml"
        response_type = "xss"
    strings:
        $path0 = "/webadmin/deny/index.php" ascii nocase
        $param0 = "policyname=auto_created" ascii nocase
        $param1 = "userip=127.0.0.1" ascii nocase
        $param2 = "connectionip=127.0.0.1" ascii nocase
        $param3 = "nsphostname=netsweeper" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_9618_netsweeper {
    meta:
        attack_type = "cve_2014_9618"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Netsweeper - Authentication Bypass: The Client Filter Admin portal in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allows remote attackers to bypass authentication and subsequently create arbitrary profiles via a showdeny action to the default URL."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9618"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9618, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9618.yaml"
        response_type = "xss"
    strings:
        $path0 = "/webadmin/clientlogin/" ascii nocase
        $param0 = "action=showdeny" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2014_9735_showbiz_pro {
    meta:
        attack_type = "cve_2014_9735"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress RevSlider - Remote Code Execution via File Upload: The ThemePunch Slider Revolution (revslider) plugin before 3.0.96 for WordPress and Showbiz Pro plugin 1.7.1 and earlier for Wordpress does not properly restrict access to administrator AJAX functionality, which."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2014-9735"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9735, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2014/CVE-2014-9735.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/revslider/temp/update_extract/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_0554_p_dga4001n_firmware {
    meta:
        attack_type = "cve_2015_0554"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ADB/Pirelli ADSL2/2+ Wireless Router P.DGA4001N - Information Disclosure: ADB (formerly Pirelli Broadband Solutions) P.DGA4001N router with firmware PDG_TEF_SP_4.06L.6 does not properly restrict access to the web interface, which allows remote attackers to obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-0554"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-0554, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-0554.yaml"
    strings:
        $path0 = "/wlsecurity.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_1000005_candidate_application_form {
    meta:
        attack_type = "cve_2015_1000005"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Candidate Application Form <= 1.3 - Local File Inclusion: WordPress Candidate Application Form <= 1.3 is susceptible to arbitrary file downloads because the code in downloadpdffile.php does not do any sanity checks."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1000005"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1000005, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1000005.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/candidate-application-form/downloadpdffile.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_1000010_simple_image_manipulator {
    meta:
        attack_type = "cve_2015_1000010"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Simple Image Manipulator < 1.0 - Local File Inclusion: WordPress Simple Image Manipulator 1.0 is vulnerable to local file inclusion in ./simple-image-manipulator/controller/download.php because no checks are made to authenticate users or sanitize input when."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1000010"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1000010, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1000010.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/./simple-image-manipulator/controller/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_1000012_mypixs {
    meta:
        attack_type = "cve_2015_1000012"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress MyPixs <=0.3 - Local File Inclusion: WordPress MyPixs 0.3 and prior contains a local file inclusion vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1000012"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1000012, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1000012.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/mypixs/mypixs/downloadpage.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_1427_elasticsearch {
    meta:
        attack_type = "cve_2015_1427"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "ElasticSearch - Remote Code Execution: ElasticSearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script to the Groovy scripting engine."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1427"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1427, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1427.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/website/blog/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_1503_mail_server {
    meta:
        attack_type = "cve_2015_1503"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IceWarp Mail Server <11.1.1 - Directory Traversal: IceWarp Mail Server versions prior to 11.1.1 suffer from a directory traversal vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1503"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1503, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1503.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/webmail/old/calendar/minimizer/index.php" ascii nocase
        $param0 = "script=..././..././..././..././..././..././..././..././..././..././etc/passwd" ascii nocase
        $param1 = "style=..././..././..././..././..././..././..././..././..././..././etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_1579_divi {
    meta:
        attack_type = "cve_2015_1579"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Slider Revolution - Local File Disclosure: Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the img parameter in a revslider_show_image action to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-1579"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1579, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-1579.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=revslider_show_image" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_20067_wp_attachment_export {
    meta:
        attack_type = "cve_2015_20067"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Attachment Export < 0.2.4 - Unrestricted File Download: The plugin does not have proper access controls, allowing unauthenticated users to download the XML data that holds all the details of attachments/posts on a Wordpress powered site. This includes details of even."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-20067"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-20067, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-20067.yaml"
    strings:
        $param0 = "content=attachment" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_2067_magmi {
    meta:
        attack_type = "cve_2015_2067"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Magento Server MAGMI - Directory Traversal: Magento Server MAGMI (aka Magento Mass Importer) contains a directory traversal vulnerability in web/ajax_pluginconf.php. that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2067"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2067, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2067.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/magmi/web/ajax_pluginconf.php" ascii nocase
        $param0 = "plugintype=utilities" ascii nocase
        $param1 = "pluginclass=CustomSQLUtility" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_2068_magmi {
    meta:
        attack_type = "cve_2015_2068"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Magento Server Mass Importer - Cross-Site Scripting: Magento Server Mass Importer plugin contains multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via the (1) profile parameter to web/magmi.php or (2) QUERY_STRING."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2068"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2068, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2068.yaml"
        response_type = "xss"
    strings:
        $path0 = "/magmi/web/magmi.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_2755_ab_google_map_travel {
    meta:
        attack_type = "cve_2015_2755"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress AB Google Map Travel <=3.4 - Stored Cross-Site Scripting: WordPress AB Google Map Travel plugin through 3.4 contains multiple stored cross-site scripting vulnerabilities. The plugin allows an attacker to hijack the administrator authentication for requests via the (1)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2755"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2755, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2755.yaml"
        response_type = "xss"
    strings:
        $param0 = "submit=Update Settings" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_2794_dotnetnuke {
    meta:
        attack_type = "cve_2015_2794"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DotNetNuke 07.04.00 - Administration Authentication Bypass: The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2794"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2794, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2794.yaml"
    strings:
        $path0 = "/Install/InstallWizard.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_2807_navis_documentcloud {
    meta:
        attack_type = "cve_2015_2807"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Navis DocumentCloud <0.1.1 - Cross-Site Scripting: Navis DocumentCloud plugin before 0.1.1 for WordPress contains a reflected cross-site scripting vulnerability in js/window.php which allows remote attackers to inject arbitrary web script or HTML via the wpbase parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2807"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2807, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2807.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/navis-documentcloud/js/window.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_2863_virtual_system_administrator {
    meta:
        attack_type = "cve_2015_2863"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Kaseya Virtual System Administrator - Open Redirect: Kaseya Virtual System Administrator 7.x before 7.0.0.29, 8.x before 8.0.0.18, 9.0 before 9.0.0.14, and 9.1 before 9.1.0.4 are susceptible to an open redirect vulnerability. An attacker can redirect users to arbitrary web."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2863"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2863, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2863.yaml"
    strings:
        $path0 = "/inc/supportLoad.asp" ascii nocase
        $path1 = "/vsaPres/Web20/core/LocalProxy.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_2996_sysaid {
    meta:
        attack_type = "cve_2015_2996"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SysAid Help Desk <15.2 - Local File Inclusion: SysAid Help Desk before 15.2 contains multiple local file inclusion vulnerabilities which can allow remote attackers to read arbitrary files via .. (dot dot) in the fileName parameter of getGfiUpgradeFile or cause a denial of."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-2996"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2996, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-2996.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/sysaid/getGfiUpgradeFile" ascii nocase
        $path1 = "/getGfiUpgradeFile" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_3648_resourcespace {
    meta:
        attack_type = "cve_2015_3648"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ResourceSpace - Local File inclusion: ResourceSpace is prone to a local file-inclusion vulnerability because it fails to sufficiently sanitize user-supplied input."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-3648"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3648, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-3648.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "defaultlanguage=../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_3897_bonita_bpm_portal {
    meta:
        attack_type = "cve_2015_3897"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bonita BPM Portal <6.5.3 - Local File Inclusion: Bonita BPM Portal before 6.5.3 allows remote attackers to read arbitrary files via a .. (dot dot) in the theme parameter and a file path in the location parameter to bonita/portal/themeResource."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-3897"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3897, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-3897.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/bonita/portal/themeResource" ascii nocase
        $param0 = "location=etc/passwd" ascii nocase
        $param1 = "location=Windows/win.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4050_symfony {
    meta:
        attack_type = "cve_2015_4050"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Symfony - Authentication Bypass: Symfony 2.3.19 through 2.3.28, 2.4.9 through 2.4.10, 2.5.4 through 2.5.11, and 2.6.0 through 2.6.7, when ESI or SSI support enabled, does not check if the _controller attribute is set, which allows remote attackers to bypass URL signing and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4050"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4050, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4050.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/_fragment" ascii nocase
        $param0 = "_path=_controller=phpcredits" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4063_newstatpress {
    meta:
        attack_type = "cve_2015_4063"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "NewStatPress <0.9.9 - Cross-Site Scripting: WordPress NewStatPress plugin before 0.9.9 contains a cross-site scripting vulnerability in includes/nsp_search.php. The plugin allows remote authenticated users to inject arbitrary web script or HTML via the where1 parameter in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4063"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4063, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4063.yaml"
        response_type = "xss"
    strings:
        $param0 = "searchsubmit=Buscar" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4074_helpdesk_pro {
    meta:
        attack_type = "cve_2015_4074"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Helpdesk Pro plugin <1.4.0 - Local File Inclusion: Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the filename parameter in a ticket.download_attachment task."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4074"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4074, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4074.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "option=com_helpdeskpro" ascii nocase
        $param1 = "task=ticket.download_attachment" ascii nocase
        $param2 = "original_filename=AnyFileName.exe" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4127_church_admin {
    meta:
        attack_type = "cve_2015_4127"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Church Admin <0.810 - Cross-Site Scripting: WordPress Church Admin plugin before 0.810 allows remote attackers to inject arbitrary web script or HTML via the address parameter via index.php/2015/05/21/church_admin-registration-form/."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4127.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/church-admin/includes/validate.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_4414_se_html5_album_audio_player {
    meta:
        attack_type = "cve_2015_4414"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress SE HTML5 Album Audio Player 1.1.0 - Directory Traversal: WordPress SE HTML5 Album Audio Player 1.1.0 contains a directory traversal vulnerability in download_audio.php that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4414"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4414, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4414.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/se-html5-album-audio-player/download_audio.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_4455_aviary_image_editor_add_on_for {
    meta:
        attack_type = "cve_2015_4455"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Plugin Aviary Image Editor Addon For Gravity Forms 3.0 Beta - Arbitrary File Upload: Unrestricted file upload vulnerability in includes/upload.php in the Aviary Image Editor Add-on For Gravity Forms plugin 3.0 beta for WordPress allows remote attackers to execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4455"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4455, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4455.yaml"
    strings:
        $param0 = "gf_page=upload" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4632_koha {
    meta:
        attack_type = "cve_2015_4632"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Koha 3.20.1 - Directory Traversal: Koha 3.14.x before 3.14.16, 3.16.x before 3.16.12, 3.18.x before 3.18.08, and 3.20.x before 3.20.1 allow remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the template_path parameter to (1)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4632"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4632, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4632.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgi-bin/koha/svc/virtualshelves/search" ascii nocase
        $param0 = "template_path=../../../../../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_4666_xsuite {
    meta:
        attack_type = "cve_2015_4666"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Xceedium Xsuite <=2.4.4.5 - Local File Inclusion: Xceedium Xsuite 2.4.4.5 and earlier is vulnerable to local file inclusion via opm/read_sessionlog.php that allows remote attackers to read arbitrary files in the logFile parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4666"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4666, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4666.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/opm/read_sessionlog.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_4668_xsuite {
    meta:
        attack_type = "cve_2015_4668"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Xsuite <=2.4.4.5 - Open Redirect: Xsuite 2.4.4.5 and prior contains an open redirect vulnerability, which can allow a remote attacker to redirect users to arbitrary web sites and conduct phishing attacks via a malicious URL in the redirurl parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4668"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4668, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4668.yaml"
    strings:
        $path0 = "/openwin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_4694_zip_attachments {
    meta:
        attack_type = "cve_2015_4694"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Zip Attachments <= 1.1.4 - Arbitrary File Retrieval: WordPress zip-attachments plugin allows arbitrary file retrieval as it does not check the download path of the requested file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-4694"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4694, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-4694.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/zip-attachments/download.php" ascii nocase
        $param0 = "za_file=../../../../../etc/passwd" ascii nocase
        $param1 = "za_filename=passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_5354_novius_os {
    meta:
        attack_type = "cve_2015_5354"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Novius OS 5.0.1-elche - Open Redirect: Novius OS 5.0.1 (Elche) allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the redirect parameter to admin/nos/login."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-5354"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5354, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-5354.yaml"
        response_type = "xss"
    strings:
        $path0 = "/novius-os/admin/nos/login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_5461_stageshow {
    meta:
        attack_type = "cve_2015_5461"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress StageShow <5.0.9 - Open Redirect: WordPress StageShow plugin before 5.0.9 contains an open redirect vulnerability in the Redirect function in stageshow_redirect.php. A remote attacker can redirect users to arbitrary web sites and conduct phishing attacks via a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-5461"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5461, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-5461.yaml"
    strings:
        $path0 = "/wp-content/plugins/stageshow/stageshow_redirect.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_5469_mdc_youtube_downloader {
    meta:
        attack_type = "cve_2015_5469"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress MDC YouTube Downloader 2.1.0 - Local File Inclusion: WordPress MDC YouTube Downloader 2.1.0 plugin is susceptible to local file inclusion. A remote attacker can read arbitrary files via a full pathname in the file parameter to includes/download.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-5469"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5469, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-5469.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/mdc-youtube-downloader/includes/download.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_5471_swim_team {
    meta:
        attack_type = "cve_2015_5471"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Swim Team <= v1.44.10777 - Local File Inclusion: The program /wp-swimteam/include/user/download.php allows unauthenticated attackers to retrieve arbitrary files from the system."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-5471"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5471, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-5471.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/wp-swimteam/include/user/download.php" ascii nocase
        $param0 = "contenttype=text/html" ascii nocase
        $param1 = "abspath=/usr/share/wordpress" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_5531_elasticsearch {
    meta:
        attack_type = "cve_2015_5531"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ElasticSearch <1.6.1 - Local File Inclusion: ElasticSearch before 1.6.1 allows remote attackers to read arbitrary files via unspecified vectors related to snapshot API calls."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-5531"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5531, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-5531.yaml"
    strings:
        $path0 = "/_snapshot/test" ascii nocase
        $path1 = "/_snapshot/test2" ascii nocase
        $path2 = "/_snapshot/test/backdata/../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_6477_nordex_control_2_scada {
    meta:
        attack_type = "cve_2015_6477"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Nordex NC2 - Cross-Site Scripting: Nordex NC2 contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-6477"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-6477, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-6477.yaml"
        response_type = "xss"
    strings:
        $param0 = "connection=basic" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_6544_itop {
    meta:
        attack_type = "cve_2015_6544"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Combodo iTop <2.2.0-2459 - Cross-Site Scripting: Combodo iTop before 2.2.0-2459 contains a cross-site scripting vulnerability in application/dashboard.class.inc.php which allows remote attackers to inject arbitrary web script or HTML via a dashboard title."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-6544"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-6544, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-6544.yaml"
        response_type = "xss"
    strings:
        $path0 = "/pages/ajax.render.php" ascii nocase
        $param0 = "operation=render_dashboard" ascii nocase
        $param1 = "layout_class=DashboardLayoutOneCol" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_6920_sourceafrica {
    meta:
        attack_type = "cve_2015_6920"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress sourceAFRICA <=0.1.3 - Cross-Site Scripting: WordPress sourceAFRICA plugin version 0.1.3 contains a cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-6920"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-6920, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-6920.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/sourceafrica/js/window.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_7245_dvg_n5402sp_firmware {
    meta:
        attack_type = "cve_2015_7245"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "D-Link DVG-N5402SP - Local File Inclusion: D-Link DVG-N5402SP is susceptible to local file inclusion in products with firmware W1000CN-00, W1000CN-03, or W2000EN-00. A remote attacker can read sensitive information via a .. (dot dot) in the errorpage parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-7245"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7245, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-7245.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgibin/webproc" ascii nocase
        $param0 = "getpage=html/index.html" ascii nocase
        $param1 = "*errorpage*=../../../../../../../../../../../etc/passwd" ascii nocase
        $param2 = "var:menu=setup" ascii nocase
        $param3 = "var:page=connected" ascii nocase
        $param4 = "objaction=auth" ascii nocase
        $param5 = ":username=blah" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_7297_joomla {
    meta:
        attack_type = "cve_2015_7297"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Core SQL Injection: A SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-7297"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7297, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-7297.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "option=com_contenthistory" ascii nocase
        $param1 = "view=history" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_7780_manageengine_firewall_analyzer {
    meta:
        attack_type = "cve_2015_7780"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ManageEngine Firewall Analyzer <8.0 - Local File Inclusion: ManageEngine Firewall Analyzer before 8.0 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-7780"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7780, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-7780.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/fw/mindex.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_7823_kentico_cms {
    meta:
        attack_type = "cve_2015_7823"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Kentico CMS 8.2 - Open Redirect: Kentico CMS 8.2 contains an open redirect vulnerability via GetDocLink.ashx with link variable. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-7823"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7823, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-7823.yaml"
    strings:
        $path0 = "/CMSPages/GetDocLink.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_8349_sourcebans {
    meta:
        attack_type = "cve_2015_8349"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SourceBans <2.0 - Cross-Site Scripting: SourceBans before 2.0 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the advSearch parameter to index.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-8349"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8349, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-8349.yaml"
        response_type = "xss"
    strings:
        $param0 = "advType=btype" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_8350_call_to_action {
    meta:
        attack_type = "cve_2015_8350"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Calls to Action <=2.4.3 - Authenticated Reflected XSS: Calls to Action plugin before 2.5.1 for WordPress contains stored XSS caused by unsanitized input in open-tab parameter in wp-admin/edit.php and wp-cta-variation-id parameter in ab-testing-call-to-action-example/."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-8350"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8350, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-8350.yaml"
        response_type = "xss"
    strings:
        $param0 = "post_type=wp-call-to-action" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_8399_confluence {
    meta:
        attack_type = "cve_2015_8399"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Confluence <5.8.17 - Information Disclosure: Atlassian Confluence before 5.8.17 contains an information disclsoure vulnerability. A remote authenticated user can read configuration files via the decoratorName parameter to (1) spaces/viewdefaultdecorator.action or (2)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-8399"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8399, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-8399.yaml"
    strings:
        $path0 = "/spaces/viewdefaultdecorator.action" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_8813_umbraco {
    meta:
        attack_type = "cve_2015_8813"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Umbraco <7.4.0- Server-Side Request Forgery: Umbraco before version 7.4.0 contains a server-side request forgery vulnerability in feedproxy.aspx that allows attackers to send arbitrary HTTP GET requests via http://local/Umbraco/feedproxy.aspx?url=http://127.0.0.1:80/index."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-8813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-8813.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/Umbraco/feedproxy.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_9406_mtheme_unus {
    meta:
        attack_type = "cve_2015_9406"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "mTheme Unus < 2.3 - Directory Traversal: The mTheme-Unus theme for WordPress, prior to version 2.3, contained a directory traversal flaw that let attackers access arbitrary files. This was possible by exploiting the files parameter in css/css.php with .. sequences."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-9406"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-9406, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-9406.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/themes/mTheme-Unus/css/css.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_9414_wp_symposium {
    meta:
        attack_type = "cve_2015_9414"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Symposium <=15.8.1 - Cross-Site Scripting: WordPress Symposium through 15.8.1 contains a reflected cross-site scripting vulnerability via the wp-content/plugins/wp-symposium/get_album_item.php?size parameter which allows an attacker to steal cookie-based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-9414"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-9414, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-9414.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wp-symposium/get_album_item.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_9415_bj_lazy_load {
    meta:
        attack_type = "cve_2015_9415"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BJ Lazy Load (Timthumb) <= 0.7.5 - Remote File Inclusion: The BJ Lazy Load plugin v0.7.5 for WordPress has a Remote File Inclusion vulnerability via TimThumb."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-9415"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-9415, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-9415.yaml"
    strings:
        $path0 = "/wp-content/plugins/bj-lazy-load/thumb.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2015_9480_robotcpa {
    meta:
        attack_type = "cve_2015_9480"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress RobotCPA 5 - Directory Traversal: The RobotCPA plugin 5 for WordPress has directory traversal via the f.php l parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-9480"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-9480, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-9480.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/robotcpa/f.php" ascii nocase
        $param0 = "l=ZmlsZTovLy9ldGMvcGFzc3dk" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2015_9499_showbiz_pro {
    meta:
        attack_type = "cve_2015_9499"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress ShowBiz Pro <= 1.7.1 - Authenticated Arbitrary File Upload to RCE: The WordPress ShowBiz Pro plugin version <= 1.7.1 allows arbitrary PHP file upload via the `admin-ajax.php` endpoint.This leads to unauthenticated remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2015-9499"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-9499, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2015/CVE-2015-9499.yaml"
    strings:
        $path0 = "/wp-content/plugins/showbizpro/temp/update_extract/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000126_admin_font_editor {
    meta:
        attack_type = "cve_2016_1000126"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Admin Font Editor <=1.8 - Cross-Site Scripting: WordPress Admin Font Editor 1.8 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000126"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000126, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000126.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/admin-font-editor/css.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000127_ajax_random_post {
    meta:
        attack_type = "cve_2016_1000127"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress AJAX Random Post <=2.00 - Cross-Site Scripting: WordPress AJAX Random Post 2.00 is vulnerable to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000127.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/ajax-random-post/js.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000128_anti_plagiarism {
    meta:
        attack_type = "cve_2016_1000128"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress anti-plagiarism <=3.60 - Cross-Site Scripting: WordPress anti-plagiarism 3.6.0 and prior are vulnerable to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000128"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000128, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000128.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/anti-plagiarism/js.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000129_defa_online_image_protector {
    meta:
        attack_type = "cve_2016_1000129"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress defa-online-image-protector <=3.3 - Cross-Site Scripting: WordPress defa-online-image-protector 3.3 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000129"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000129, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000129.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/defa-online-image-protector/redirect.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000131_esearch {
    meta:
        attack_type = "cve_2016_1000131"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress e-search <=1.0 - Cross-Site Scripting: WordPress e-search 1.0 and before contains a reflected cross-site scripting vulnerability via title_az.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000131"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000131, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000131.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/e-search/tmpl/title_az.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000132_tooltip_glossary {
    meta:
        attack_type = "cve_2016_1000132"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress enhanced-tooltipglossary 3.2.8 - Cross-Site Scripting: WordPress enhanced-tooltipglossary 3.2.8 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000132"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000132, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000132.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/enhanced-tooltipglossary/backend/views/admin_importexport.php" ascii nocase
        $param0 = "msg=imported" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_1000133_forget_about_shortcode_buttons {
    meta:
        attack_type = "cve_2016_1000133"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress forget-about-shortcode-buttons 1.1.1 - Cross-Site Scripting: Wordpress plugin forget-about-shortcode-buttons 1.1.1 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000133.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/forget-about-shortcode-buttons/assets/js/fasc-buttons/popup.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000134_hdw_tube {
    meta:
        attack_type = "cve_2016_1000134"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress HDW Video Gallery <=1.2 - Cross-Site Scripting: WordPress HDW Video Gallery 1.2 and before contains a cross-site scripting vulnerability via playlist.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000134.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/hdw-tube/playlist.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000135_hdw_tube {
    meta:
        attack_type = "cve_2016_1000135"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress HDW Video Gallery <=1.2 - Cross-Site Scripting: WordPress HDW Video Gallery 1.2 and before contains a cross-site scripting vulnerability via mychannel.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000135"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000135, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000135.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/hdw-tube/mychannel.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000136_heat_trackr {
    meta:
        attack_type = "cve_2016_1000136"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress heat-trackr 1.0 - Cross-Site Scripting: WordPress heat-trackr 1.0 contains a cross-site scripting vulnerability via heat-trackr_abtest_add.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000136.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/heat-trackr/heat-trackr_abtest_add.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000137_hero_maps_pro {
    meta:
        attack_type = "cve_2016_1000137"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Hero Maps Pro 2.1.0 - Cross-Site Scripting: WordPress Hero Maps Pro 2.1.0 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000137.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/hero-maps-pro/views/dashboard/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000138_indexisto {
    meta:
        attack_type = "cve_2016_1000138"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Admin Font Editor <=1.8 - Cross-Site Scripting: WordPress Admin Font Editor plugin indexisto 1.8 and before contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000138.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/indexisto/assets/js/indexisto-inject.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000139_infusionsoft {
    meta:
        attack_type = "cve_2016_1000139"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Infusionsoft Gravity Forms <=1.5.11 - Cross-Site Scripting: WordPress plugin Infusionsoft 1.5.11 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000139"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000139, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000139.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/infusionsoft/Infusionsoft/examples/leadscoring.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000140_new_year_firework {
    meta:
        attack_type = "cve_2016_1000140"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress New Year Firework <=1.1.9 - Cross-Site Scripting: WordPress New Year Firework 1.1.9 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000140"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000140, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000140.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/new-year-firework/firework/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000141_page_layout_builder {
    meta:
        attack_type = "cve_2016_1000141"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Page Layout builder v1.9.3 - Cross-Site Scripting: WordPress plugin Page-layout-builder v1.9.3 contains a cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000141"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000141, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000141.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/page-layout-builder/includes/layout-settings.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000142_parsi_font {
    meta:
        attack_type = "cve_2016_1000142"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress MW Font Changer <=4.2.5 - Cross-Site Scripting: WordPress MW Font Changer plugin 4.2.5 and before contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000142"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000142, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000142.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/parsi-font/css.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000143_photoxhibit {
    meta:
        attack_type = "cve_2016_1000143"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Photoxhibit 2.1.8 - Cross-Site Scripting: WordPress Photoxhibit 2.1.8 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000143"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000143, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000143.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/photoxhibit/common/inc/pages/build.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000146_pondol_formmail {
    meta:
        attack_type = "cve_2016_1000146"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Pondol Form to Mail <=1.1 - Cross-Site Scripting: WordPress Pondol Form to Mail 1.1 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000146"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000146, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000146.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/pondol-formmail/pages/admin-mail-info.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000148_s3_video {
    meta:
        attack_type = "cve_2016_1000148"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress S3 Video <=0.983 - Cross-Site Scripting: WordPress S3 Video and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000148"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000148, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000148.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/s3-video/views/video-management/preview_video.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000149_simpel_reserveren {
    meta:
        attack_type = "cve_2016_1000149"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Simpel Reserveren <=3.5.2 - Cross-Site Scripting: WordPress plugin Simpel Reserveren 3.5.2 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000149"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000149, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000149.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/simpel-reserveren/edit.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000152_tidio_form {
    meta:
        attack_type = "cve_2016_1000152"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Tidio-form <=1.0 - Cross-Site Scripting: WordPress tidio-form1.0 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000152"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000152, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000152.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/tidio-form/popup-insert-help.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000153_tidio_gallery {
    meta:
        attack_type = "cve_2016_1000153"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Tidio Gallery <=1.1 - Cross-Site Scripting: WordPress plugin tidio-gallery v1.1 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000153.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/tidio-gallery/popup-insert-help.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000154_whizz {
    meta:
        attack_type = "cve_2016_1000154"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WHIZZ <=1.0.7 - Cross-Site Scripting: WordPress plugin WHIZZ 1.07 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000154"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000154, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000154.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/whizz/plugins/delete-plugin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1000155_wpsolr_search_engine {
    meta:
        attack_type = "cve_2016_1000155"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPSOLR <=8.6 - Cross-Site Scripting: WordPress WPSOLR 8.6 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1000155"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1000155, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1000155.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wpsolr-search-engine/classes/extensions/managed-solr-servers/templates/template-my-accounts.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_10134_zabbix {
    meta:
        attack_type = "cve_2016_10134"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zabbix - SQL Injection: Zabbix before 2.2.14 and 3.0 before 3.0.4 allows remote attackers to execute arbitrary SQL commands via the toggle_ids array parameter in latest.php and perform SQL injection attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10134.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/jsrpc.php" ascii nocase
        $param0 = "profileIdx=web.item.graph" ascii nocase
        $param1 = "profileIdx2=updatexml(0,concat(0xa,user()),0)::" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_10367_opsview {
    meta:
        attack_type = "cve_2016_10367"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Opsview Monitor Pro - Local File Inclusion: Opsview Monitor Pro prior to 5.1.0.162300841, prior to 5.0.2.27475, prior to 4.6.4.162391051, and 4.5.x without a certain 2016 security patch is vulnerable to unauthenticated local file inclusion and can be exploited by issuing a."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10367"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10367, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10367.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/monitoring/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_10924_zedna_ebook_download {
    meta:
        attack_type = "cve_2016_10924"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress Zedna eBook download <1.2 - Local File Inclusion: Wordpress Zedna eBook download prior to version 1.2 was affected by a filedownload.php local file inclusion vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10924"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10924, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10924.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/ebook-download/filedownload.php" ascii nocase
        $param0 = "ebookdownloadurl=../../../wp-config.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_10940_zm_gallery {
    meta:
        attack_type = "cve_2016_10940"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress zm-gallery plugin 1.0 SQL Injection: zm-gallery plugin 1.0 for WordPress is susceptible to SQL injection via the order parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10940.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "page=zm_gallery" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_10956_mail_masta {
    meta:
        attack_type = "cve_2016_10956"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Mail Masta 1.0 - Local File Inclusion: WordPress Mail Masta 1.0 is susceptible to local file inclusion in count_of_send.php and csvexport.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10956.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php" ascii nocase
        $path1 = "/wp-content/plugins/mail-masta/inc/lists/csvexport.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_10960_wsecure {
    meta:
        attack_type = "cve_2016_10960"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress wSecure Lite < 2.4 - Remote Code Execution: WordPress wsecure plugin before 2.4 is susceptible to remote code execution via shell metacharacters in the wsecure-config.php publish parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10960"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10960, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10960.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/wsecure/wsecure-config.php" ascii nocase
        $param0 = "wsecure_action=update" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_10973_brafton {
    meta:
        attack_type = "cve_2016_10973"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Brafton WordPress Plugin < 3.4.8 - Cross-Site Scripting: The Brafton plugin before 3.4.8 for WordPress has XSS via the wp-admin/admin.php?page=BraftonArticleLoader tab parameter to BraftonAdminPage.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-10973"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10973, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-10973.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=BraftonArticleLoader" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_15043_wp_mobile_detector_3_5 {
    meta:
        attack_type = "cve_2016_15043"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Mobile Detector <= 3.5 - Unrestricted File Upload: WP Mobile Detector plugin for WordPress <= 3.5 contains an unrestricted file upload vulnerability caused by missing file type validation in resize.php, letting unauthenticated attackers upload arbitrary files, potentially."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-15043"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-15043, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-15043.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/wp-mobile-detector/resize.php" ascii nocase
        $path1 = "/wp-content/plugins/wp-mobile-detector/cache/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_1555_wnap320_firmware {
    meta:
        attack_type = "cve_2016_1555"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "NETGEAR WNAP320 Access Point Firmware - Remote Command Injection: NETGEAR WNAP320 Access Point Firmware version 2.0.3 could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-1555"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1555, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-1555.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/boardDataWW.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_2389_netweaver {
    meta:
        attack_type = "cve_2016_2389"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SAP xMII 15.0 for SAP NetWeaver 7.4 - Local File Inclusion: SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the path parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-2389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-2389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-2389.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/XMII/Catalog" ascii nocase
        $param0 = "Mode=GetFileList" ascii nocase
        $param1 = "Path=Classes/../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_3081_struts {
    meta:
        attack_type = "cve_2016_3081"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache S2-032 Struts - Remote Code Execution: Apache Struts 2.3.19 to 2.3.20.2, 2.3.21 to 2.3.24.1, and 2.3.25 to 2.3.28, when dynamic method invocation is enabled, allows remote attackers to execute arbitrary code via method: prefix (related to chained expressions)."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-3081"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3081, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-3081.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "encoding=UTF-8" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_3088_activemq {
    meta:
        attack_type = "cve_2016_3088"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Apache ActiveMQ Fileserver - Arbitrary File Write: Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request via the Fileserver web application."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-3088"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3088, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-3088.yaml"
    strings:
        $path0 = "/fileserver/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_4977_spring_security_oauth {
    meta:
        attack_type = "cve_2016_4977"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Spring Security OAuth2 Remote Command Execution: Spring Security OAuth versions 2.0.0 to 2.0.9 and 1.0.0 to 1.0.5 contain a remote command execution vulnerability. When processing authorization requests using the whitelabel views, the response_type parameter value was executed."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-4977"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4977, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-4977.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/oauth/authorize" ascii nocase
        $param0 = "client_id=acme" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_5649_dgn2200_firmware {
    meta:
        attack_type = "cve_2016_5649"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NETGEAR DGN2200 / DGND3700 - Admin Password Disclosure: NETGEAR DGN2200 / DGND3700 is susceptible to a vulnerability within the page 'BSW_cxttongr.htm' which can allow a remote attacker to access this page without any authentication. The attacker can then use this password to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-5649"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-5649, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-5649.yaml"
    strings:
        $path0 = "/BSW_cxttongr.htm" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_5674_readynas_surveillance {
    meta:
        attack_type = "cve_2016_5674"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NUUO NVR camera `debugging_center_utils_.php` - Command Execution: __debugging_center_utils___.php in NUUO NVRmini 2 1.7.5 through 3.0.0, NUUO NVRsolo 1.7.5 through 3.0.0, and NETGEAR ReadyNAS Surveillance 1.1.1 through 1.4.1 allows remote attackers to execute arbitrary PHP."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-5674"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-5674, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-5674.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/__debugging_center_utils___.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_6195_vbulletin {
    meta:
        attack_type = "cve_2016_6195"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "vBulletin <= 4.2.3 - SQL Injection: vBulletin versions 3.6.0 through 4.2.3 are vulnerable to an SQL injection vulnerability in the vBulletin core forumrunner addon. The vulnerability allows an attacker to execute arbitrary SQL queries and potentially access sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-6195"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-6195, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-6195.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/forumrunner/request.php" ascii nocase
        $path1 = "/boards/forumrunner/request.php" ascii nocase
        $path2 = "/board/forumrunner/request.php" ascii nocase
        $path3 = "/forum/forumrunner/request.php" ascii nocase
        $path4 = "/forums/forumrunner/request.php" ascii nocase
        $path5 = "/vb/forumrunner/request.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_6601_webnms_framework {
    meta:
        attack_type = "cve_2016_6601"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ZOHO WebNMS Framework <5.2 SP1 - Local File Inclusion: ZOHO WebNMS Framework before version 5.2 SP1 is vulnerable local file inclusion which allows an attacker to read arbitrary files via a .. (dot dot) in the fileName parameter to servlets/FetchFile."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-6601"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-6601, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-6601.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/servlets/FetchFile" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_7552_threat_discovery_appliance {
    meta:
        attack_type = "cve_2016_7552"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass: Trend Micro Threat Discovery Appliance 2.6.1062r1 is vulnerable to a directory traversal vulnerability when processing a session_id cookie, which allows a remote, unauthenticated attacker to delete."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-7552"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7552, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-7552.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgi-bin/logoff.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_7834_snc_series_firmware {
    meta:
        attack_type = "cve_2016_7834"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sony IPELA Engine IP Camera - Hardcoded Account: Multiple SONY network cameras are vulnerable to sensitive information disclosure via hardcoded credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-7834"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7834, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-7834.yaml"
    strings:
        $path0 = "/command/prima-factory.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2016_7981_spip {
    meta:
        attack_type = "cve_2016_7981"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SPIP <3.1.2 - Cross-Site Scripting: SPIP 3.1.2 and earlier contains a cross-site scripting vulnerability in valider_xml.php which allows remote attackers to inject arbitrary web script or HTML via the var_url parameter in a valider_xml action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-7981"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7981, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-7981.yaml"
        response_type = "xss"
    strings:
        $param0 = "exec=valider_xml" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2016_8527_airwave {
    meta:
        attack_type = "cve_2016_8527"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Aruba Airwave <8.2.3.1 - Cross-Site Scripting: Aruba Airwave before version 8.2.3.1 is vulnerable to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2016-8527"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8527, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-8527.yaml"
        response_type = "xss"
    strings:
        $path0 = "/visualrf/group_list.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_0929_dotnetnuke {
    meta:
        attack_type = "cve_2017_0929"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DotNetNuke (DNN) ImageHandler <9.2.0 - Server-Side Request Forgery: DotNetNuke (aka DNN) before 9.2.0 suffers from a server-side request forgery vulnerability in the DnnImageHandler class. Attackers may be able to access information about internal network resources."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-0929"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0929, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-0929.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/DnnImageHandler.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_1000170_jqueryfiletree {
    meta:
        attack_type = "cve_2017_1000170"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Delightful Downloads Jquery File Tree 2.1.5 - Local File Inclusion: WordPress Delightful Downloads Jquery File Tree versions 2.1.5 and older are susceptible to local file inclusion vulnerabilities via jqueryFileTree."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-1000170"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000170, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-1000170.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_1000486_primefaces {
    meta:
        attack_type = "cve_2017_1000486"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Primetek Primefaces 5.x - Remote Code Execution: Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-1000486"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000486, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-1000486.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/javax.faces.resource/dynamiccontent.properties.xhtml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_10075_webcenter_content {
    meta:
        attack_type = "cve_2017_10075"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Content Server - Cross-Site Scripting: Oracle Content Server version 11.1.1.9.0, 12.2.1.1.0 and 12.2.1.2.0 are susceptible to cross-site scripting. The vulnerability can be used to include HTML or JavaScript code in the affected web page. The code is executed in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-10075"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-10075, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-10075.yaml"
        response_type = "xss"
    strings:
        $path0 = "/cs/idcplg" ascii nocase
        $param0 = "IdcService=GET_SEARCH_RESULTS" ascii nocase
        $param1 = "ResultTemplate=StandardResults" ascii nocase
        $param2 = "PageName=indext" ascii nocase
        $param3 = "SortField=dInDate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_11107_phpldapadmin {
    meta:
        attack_type = "cve_2017_11107"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpLDAPadmin <= 1.2.3 - Reflected XSS: phpLDAPadmin <= 1.2.3 contains a reflected cross-site scripting caused by unsanitized input in htdocs/entry_chooser.php via the form, element, rdn, or container parameter, letting attackers execute malicious scripts in victim browsers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-11107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11107, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-11107.yaml"
        response_type = "xss"
    strings:
        $path0 = "/phpldapadmin/" ascii nocase
        $path1 = "/phpldapadmin/entry_chooser.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_11165_dt80_dex_firmware {
    meta:
        attack_type = "cve_2017_11165"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DataTaker DT80 dEX 1.50.012 - Information Disclosure: DataTaker DT80 dEX 1.50.012 is susceptible to information disclosure. A remote attacker can obtain sensitive credential and configuration information via a direct request for the /services/getFile.cmd?userfile=config.xml."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-11165"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11165, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-11165.yaml"
    strings:
        $path0 = "/services/getFile.cmd" ascii nocase
        $param0 = "userfile=config.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_11444_subrion_cms {
    meta:
        attack_type = "cve_2017_11444"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Subrion CMS <4.1.5.10 - SQL Injection: Subrion CMS before 4.1.5.10 has a SQL injection vulnerability in /front/search.php via the $_GET array."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-11444"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11444, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-11444.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/search/members/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_11512_servicedesk {
    meta:
        attack_type = "cve_2017_11512"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ManageEngine ServiceDesk 9.3.9328 - Arbitrary File Retrieval: ManageEngine ServiceDesk 9.3.9328 is vulnerable to an arbitrary file retrieval due to improper restrictions of the pathname used in the name parameter for the download-snapshot path. An unauthenticated remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-11512"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11512, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-11512.yaml"
    strings:
        $path0 = "/fosagent/repl/download-file" ascii nocase
        $path1 = "/fosagent/repl/download-snapshot" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_12138_xoops {
    meta:
        attack_type = "cve_2017_12138"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XOOPS Core 2.5.8 - Open Redirect: XOOPS Core 2.5.8 contains an open redirect vulnerability in /modules/profile/index.php due to the URL filter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12138.yaml"
    strings:
        $path0 = "/modules/profile/index.php" ascii nocase
        $param0 = "xoops_redirect=/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_12149_jboss_enterprise_application_p {
    meta:
        attack_type = "cve_2017_12149"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Jboss Application Server - Remote Code Execution: Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2 is susceptible to a remote code execution vulnerability because the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12149"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12149, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12149.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/invoker/JMXInvokerServlet/" ascii nocase
        $path1 = "/invoker/EJBInvokerServlet/" ascii nocase
        $path2 = "/invoker/readonly" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_12542_integrated_lights_out_4_firmwa {
    meta:
        attack_type = "cve_2017_12542"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "HPE Integrated Lights-out 4 (ILO4) <2.53 - Authentication Bypass: HPE Integrated Lights-out 4 (iLO 4) prior to 2.53 was found to contain an authentication bypass and code execution vulnerability."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12542"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12542, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12542.yaml"
    strings:
        $path0 = "/rest/v1/AccountService/Accounts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_12544_system_management_homepage {
    meta:
        attack_type = "cve_2017_12544"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HPE System Management - Cross-Site Scripting: HPE System Management contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12544"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12544, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12544.yaml"
        response_type = "xss"
    strings:
        $path0 = "/gsearch.php.en" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_12583_dokuwiki {
    meta:
        attack_type = "cve_2017_12583"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DokuWiki - Cross-Site Scripting: DokuWiki through 2017-02-19b contains a cross-site scripting vulnerability in the DATE_AT parameter to doku.php which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12583"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12583, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12583.yaml"
        response_type = "xss"
    strings:
        $path0 = "/dokuwiki/doku.php" ascii nocase
        $param0 = "id=wiki:welcome" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_12629_solr {
    meta:
        attack_type = "cve_2017_12629"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Solr <= 7.1 - XML Entity Injection: Apache Solr with Apache Lucene before 7.1 is susceptible to remote code execution by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12629"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12629, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12629.yaml"
    strings:
        $param0 = "defType=xmlparser" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_12635_couchdb {
    meta:
        attack_type = "cve_2017_12635"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache CouchDB 1.7.0 / 2.x < 2.1.1 - Remote Privilege Escalation: Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keysfor 'roles'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-12635"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12635, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12635.yaml"
    strings:
        $path0 = "/_users/org.couchdb.user:poc" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_14135_opendreambox {
    meta:
        attack_type = "cve_2017_14135"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenDreambox 2.0.0 - Remote Code Execution: OpenDreambox 2.0.0 is susceptible to remote code execution via the webadmin plugin. Remote attackers can execute arbitrary OS commands via shell metacharacters in the command parameter to the /script URI in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-14135"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-14135, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14135.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/webadmin/script" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_14186_fortios {
    meta:
        attack_type = "cve_2017_14186"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FortiGate FortiOS SSL VPN Web Portal - Cross-Site Scripting: FortiGate FortiOS through SSL VPN Web Portal contains a cross-site scripting vulnerability. The login redir parameter is not sanitized, so an attacker can inject arbitrary script in the browser of an unsuspecting user."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-14186"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-14186, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14186.yaml"
        response_type = "xss"
    strings:
        $path0 = "/remote/loginredir" ascii nocase
        $param0 = "redir=javascript:alert(document.domain)" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_14537_trixbox {
    meta:
        attack_type = "cve_2017_14537"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Trixbox 2.8.0 - Path Traversal: Trixbox 2.8.0.4 is susceptible to path traversal via the xajaxargs array parameter to /maint/index.php?packages or the lang parameter to /maint/modules/home/index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-14537"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-14537, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14537.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/maint/index.php" ascii nocase
        $param0 = "xajaxargs[]=../../../../../../../../../../../../../../../../etc/passwd" ascii nocase
        $param1 = "xajaxargs[]=yumPackages" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_14651_api_manager {
    meta:
        attack_type = "cve_2017_14651"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 Data Analytics Server 3.1.0 - Cross-Site Scripting: WSO2 Data Analytics Server 3.1.0 is susceptible to cross-site scripting in carbon/resources/add_collection_ajaxprocessor.jsp via the collectionName or parentPath parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-14651"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-14651, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14651.yaml"
        response_type = "xss"
    strings:
        $path0 = "/carbon/resources/add_collection_ajaxprocessor.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_14725_wordpress {
    meta:
        attack_type = "cve_2017_14725"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress < 4.8.2 - Authenticated Open Redirect: WordPress versions before 4.8.2 contain an open redirect caused by improper validation in wp-admin/edit-tag-form.php and wp-admin/user-edit.php, letting attackers redirect users to malicious sites, exploit requires access to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-14725"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-14725, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14725.yaml"
    strings:
        $param0 = "taxonomy=category" ascii nocase
        $param1 = "action=editedtag" ascii nocase
        $param2 = "name=Uncategorized" ascii nocase
        $param3 = "slug=uncategorized" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_15287_bouqueteditor {
    meta:
        attack_type = "cve_2017_15287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Dreambox WebControl 2.0.0 - Cross-Site Scripting: Dream Multimedia Dreambox devices via their WebControl component are vulnerable to reflected cross-site scripting, as demonstrated by the 'Name des Bouquets' field, or the file parameter to the /file URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-15287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-15287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-15287.yaml"
        response_type = "xss"
    strings:
        $path0 = "/webadmin/pkg" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_15363_restler {
    meta:
        attack_type = "cve_2017_15363"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 - Local File Inclusion: Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 is susceptible to local file inclusion in public/examples/resources/getsource.php. This could allow remote attackers to read arbitrary files via the file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-15363"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-15363, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-15363.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/typo3conf/ext/restler/vendor/luracast/restler/public/examples/resources/getsource.php" ascii nocase
        $param0 = "file=../../../../../../../LocalConfiguration.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_15647_routerfiberhome_firmware {
    meta:
        attack_type = "cve_2017_15647"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FiberHome Routers - Local File Inclusion: FiberHome routers are susceptible to local file inclusion in /cgi-bin/webproc via the getpage parameter in conjunction with a crafted var:page value."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-15647"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-15647, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-15647.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "var:language=en_us" ascii nocase
        $param1 = "var:page=wizardfifth" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_15944_pan_os {
    meta:
        attack_type = "cve_2017_15944"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Palo Alto Network PAN-OS - Remote Code Execution: Palo Alto Network PAN-OS and Panorama before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-15944"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-15944, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-15944.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/esp/cms_changeDeviceContext.esp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_17043_emag_marketplace_connector {
    meta:
        attack_type = "cve_2017_17043"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Emag Marketplace Connector 1.0 - Cross-Site Scripting: WordPress Emag Marketplace Connector plugin 1.0 contains a reflected cross-site scripting vulnerability because the parameter 'post' to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17043"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17043, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17043.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/emag-marketplace-connector/templates/order/awb-meta-box.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_17059_amtythumb {
    meta:
        attack_type = "cve_2017_17059"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress amtyThumb Posts 8.1.3 - Cross-Site Scripting: WordPress amty-thumb-recent-post plugin 8.1.3 contains a cross-site scripting vulnerability via the query string to amtyThumbPostsAdminPg.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17059.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/amty-thumb-recent-post/amtyThumbPostsAdminPg.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_17451_wp_mailster {
    meta:
        attack_type = "cve_2017_17451"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Mailster <=1.5.4 - Cross-Site Scripting: WordPress Mailster 1.5.4 and before contains a cross-site scripting vulnerability in the unsubscribe handler via the mes parameter to view/subscription/unsubscribe2.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17451"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17451, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17451.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wp-mailster/view/subscription/unsubscribe2.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_17562_goahead {
    meta:
        attack_type = "cve_2017_17562"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Embedthis GoAhead <3.6.5 - Remote Code Execution: description: Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17562, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17562.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "LD_DEBUG=help" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_17731_dedecms {
    meta:
        attack_type = "cve_2017_17731"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DedeCMS 5.7 - SQL Injection: DedeCMS through 5.7 has SQL Injection via the $_FILES superglobal to plus/recommend.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17731"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17731, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17731.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/plus/recommend.php" ascii nocase
        $param0 = "_FILES[type][name]=1.jpg" ascii nocase
        $param1 = "_FILES[type][type]=application/octet-stream" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_17736_kentico_cms {
    meta:
        attack_type = "cve_2017_17736"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kentico - Installer Privilege Escalation: Kentico 9.0 before 9.0.51 and 10.0 before 10.0.48 are susceptible to a privilege escalation attack. An attacker can obtain Global Administrator access by visiting CMSInstall/install.aspx and then navigating to the CMS Administration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17736"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17736, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17736.yaml"
    strings:
        $path0 = "/CMSInstall/install.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_17762_episerver {
    meta:
        attack_type = "cve_2017_17762"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Episerver 7 - Blind XML External Entity Injection: Episerver 7 patch 4 and earlier contains an XML external entity (XXE) caused by processing crafted DTD in XML requests involving util/xmlrpc/Handler.ashx, letting remote attackers read arbitrary files, exploit requires sending."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-17762"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17762, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-17762.yaml"
    strings:
        $path0 = "/util/xmlrpc/Handler.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_18349_fastjson {
    meta:
        attack_type = "cve_2017_18349"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fastjson Insecure Deserialization - Remote Code Execution: parseObject in Fastjson before 1.2.25, as used in FastjsonEngine in Pippo 1.11.0 and other products, allows remote attackers to execute arbitrary code via a crafted JSON request, as demonstrated by a crafted rmi-// URI."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-18349"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-18349, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18349.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/deserialize" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_18362_manageditsync {
    meta:
        attack_type = "cve_2017_18362"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Kaseya VSA 2017 ConnectWise ManagedITSync - Remote Code Execution: ConnectWise ManagedITSync integration through 2017 for Kaseya VSA is vulnerable to unauthenticated remote commands that allow full direct access to the Kaseya VSA database. If the ManagedIT.asmx page is."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-18362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-18362, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18362.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/KaseyaCwWebService/ManagedIT.asmx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_18598_qards {
    meta:
        attack_type = "cve_2017_18598"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Qards - Cross-Site Scripting: WordPress Qards through 2017-10-11 contains a cross-site scripting vulnerability via a remote document specified in the URL parameter to html2canvasproxy.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-18598"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-18598, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18598.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/wp-content/plugins/qards/html2canvasproxy.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_18638_graphite {
    meta:
        attack_type = "cve_2017_18638"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Graphite <=1.1.5 - Server-Side Request Forgery: Graphite's send_email in graphite-web/webapp/graphite/composer/views.py in versions up to 1.1.5 is vulnerable to server-side request forgery (SSR)F. The vulnerable SSRF endpoint can be used by an attacker to have the Graphite web."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-18638"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-18638, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18638.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/composer/send_email" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_20192_formidable_forms_2_05_02 {
    meta:
        attack_type = "cve_2017_20192"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Formidable Forms < 2.05.02 - Cross-Site Scripting: Formidable Form Builder for WordPress versions before 2.05.03 contains a stored cross-site scripting caused by insufficient input sanitization and output escaping in form parameters like 'after_html', letting unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-20192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-20192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-20192.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=frm_forms_preview" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_3132_fortios {
    meta:
        attack_type = "cve_2017_3132"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Fortinet FortiOS < 5.6.0 - Cross-Site Scripting: A Cross-Site Scripting vulnerability in Fortinet FortiOS versions 5.6.0 and earlier allows attackers to Execute unauthorized code or commands via the action input during the activation of a FortiToken."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-3132"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-3132, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-3132.yaml"
        response_type = "xss"
    strings:
        $path0 = "/p/user/ftoken/activate/user/guest/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_3133_fortios {
    meta:
        attack_type = "cve_2017_3133"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Fortinet FortiOS < 5.6.0 - Cross-Site Scripting: A Cross-Site Scripting vulnerability in Fortinet FortiOS versions 5.6.0 and earlier allows attackers to execute unauthorized code or commands via the Replacement Message HTML for SSL-VPN."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-3133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-3133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-3133.yaml"
        response_type = "xss"
    strings:
        $path0 = "/p/system/replacemsg/edit/sslvpn/sslvpn-login/" ascii nocase
        $path1 = "/p/system/replacemsg-group/edit/None/sslvpn/sslvpn-login/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_3506_weblogic_server {
    meta:
        attack_type = "cve_2017_3506"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Oracle Fusion Middleware Weblogic Server - Remote OS Command Execution: The Oracle WebLogic Server component of Oracle Fusion Middleware (Web Services) versions 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2 is susceptible to a difficult to exploit vulnerability that could."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-3506"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-3506, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-3506.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wls-wsat/RegistrationRequesterPortType" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_5521_r6200_firmware {
    meta:
        attack_type = "cve_2017_5521"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "NETGEAR Routers - Authentication Bypass: NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices are susceptible to authentication bypass via simple crafted requests to the web management server."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-5521"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5521, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-5521.yaml"
    strings:
        $path0 = "/passwordrecovered.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_5871_odoo {
    meta:
        attack_type = "cve_2017_5871"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Odoo <= 8.0-20160726 & 9.0 - Open Redirect: An Open Redirect vulnerability in Odoo versions <= 8.0-20160726 and 9.0. This issue allows an attacker to redirect users to untrusted sites via a crafted URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-5871"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5871, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-5871.yaml"
    strings:
        $path0 = "/web/dbredirect" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_5982_kodi {
    meta:
        attack_type = "cve_2017_5982"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kodi 17.1 - Local File Inclusion: Kodi 17.1 is vulnerable to local file inclusion vulnerabilities because of insufficient validation of user input."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-5982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-5982.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/image/image:/..%2fetc%2fpasswd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_5983_jira {
    meta:
        attack_type = "cve_2017_5983"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JIRA Workflow Designer Plugin in Atlassian JIRA Server > 6.3.0 - Remote Code Execution (XXE): The JIRA Workflow Designer Plugin in Atlassian JIRA Server before 6.3.0 improperly uses an XML parser and deserializer, which allows remote attackers to execute arbitrary code, read."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-5983"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5983, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-5983.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/secure/Dashboard.jspa" ascii nocase
        $path1 = "/jira/secure/Dashboard.jspa" ascii nocase
        $path2 = "/plugins/servlet/jwd/amf/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_6090_phpcollab {
    meta:
        attack_type = "cve_2017_6090"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PhpColl 2.5.1 Arbitrary File Upload: PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/ via clients/editclient.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-6090"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-6090, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-6090.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/logos_clients/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_7391_magmi {
    meta:
        attack_type = "cve_2017_7391"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Magmi 0.7.22 - Cross-Site Scripting: Magmi 0.7.22 contains a cross-site scripting vulnerability due to insufficient filtration of user-supplied data (prefix) passed to the magmi-git-master/magmi/web/ajax_gettime.php URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-7391"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7391, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-7391.yaml"
        response_type = "xss"
    strings:
        $path0 = "/magmi/web/ajax_gettime.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_7504_jboss_application_server {
    meta:
        attack_type = "cve_2017_7504"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JBossMQ HTTP Invocation Layer (HTTPServerILServlet) - Unauthenticated Java Deserialization: The JMS over HTTP Invocation Layer in JBossMQ, as implemented in HTTPServerILServlet.java in JBoss Application Server (AS) 4.x and earlier, does not properly restrict the classes that."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-7504"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7504, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-7504.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/jbossmq-httpil/HTTPServerILServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_7615_mantisbt {
    meta:
        attack_type = "cve_2017_7615"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MantisBT <=2.30 - Arbitrary Password Reset/Admin Access: MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated admin access via an empty confirm_hash value to verify.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-7615"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7615, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-7615.yaml"
    strings:
        $path0 = "/verify.php" ascii nocase
        $path1 = "/mantis/verify.php" ascii nocase
        $path2 = "/mantisBT/verify.php" ascii nocase
        $path3 = "/mantisbt-2.3.0/verify.php" ascii nocase
        $path4 = "/bugs/verify.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_7925_dh_ipc_hdbw23a0rn_zs_firmware {
    meta:
        attack_type = "cve_2017_7925"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua Security - Configuration File Disclosure: A Password in Configuration File issue was discovered in Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC-HDW1XXX, DH-IPC-HDW2XXX, DH-IPC-HDW4XXX, DH-IPC-HFW1XXX, DH-IPC-HFW2XXX, DH-IPC-HFW4XXX, DH-SD6CXX, DH-NVR1XXX."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-7925"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7925, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-7925.yaml"
    strings:
        $path0 = "/current_config/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_8229_ipm_721s_firmware {
    meta:
        attack_type = "cve_2017_8229"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Amcrest IP Camera Web Management - Data Exposure: Amcrest IPM-721S V2.420.AC00.16.R.20160909 devices allow an unauthenticated attacker to download the administrative credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-8229"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-8229, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-8229.yaml"
    strings:
        $path0 = "/current_config/Sha1Account1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_8917_joomla {
    meta:
        attack_type = "cve_2017_8917"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla! <3.7.1 - SQL Injection: Joomla! before 3.7.1 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-8917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-8917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-8917.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "layout=modal" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_9140_telerik_reporting {
    meta:
        attack_type = "cve_2017_9140"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Reflected XSS - Telerik Reporting Module: Cross-site scripting vulnerability in Telerik.ReportViewer.WebForms.dll in Telerik Reporting for ASP.NET WebForms Report Viewer control before R1 2017 SP2 (11.0.17.406) allows remote attackers to inject arbitrary web script or HTML via."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9140"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9140, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9140.yaml"
        response_type = "xss"
    strings:
        $path0 = "/Telerik.ReportViewer.axd" ascii nocase
        $param0 = "optype=Parameters" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2017_9288_raygun4wp {
    meta:
        attack_type = "cve_2017_9288"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Raygun4WP <=1.8.0 - Cross-Site Scripting: WordPress Raygun4WP 1.8.0 contains a reflected cross-site scripting vulnerability via sendtesterror.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9288"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9288, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9288.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/raygun4wp/sendtesterror.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_9506_oauth {
    meta:
        attack_type = "cve_2017_9506"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Jira IconURIServlet - Cross-Site Scripting/Server-Side Request Forgery: The Atlassian Jira IconUriServlet of the OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 contains a cross-site scripting vulnerability which."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9506"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9506, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9506.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/plugins/servlet/oauth/users/icon-uri" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_9791_struts {
    meta:
        attack_type = "cve_2017_9791"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Apache Struts2 S2-053 - Remote Code Execution: Apache Struts 2.1.x and 2.3.x with the Struts 1 plugin might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9791"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9791, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9791.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/integration/saveGangster.action" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_9805_struts {
    meta:
        attack_type = "cve_2017_9805"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Struts2 S2-052 - Remote Code Execution: The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type of filtering, which can lead to remote code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9805"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9805, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9805.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/struts2-rest-showcase/orders/3" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2017_9833_boa {
    meta:
        attack_type = "cve_2017_9833"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BOA Web Server 0.94.14 - Arbitrary File Access: BOA Web Server 0.94.14 is susceptible to arbitrary file access. The server allows the injection of '../..' using the FILECAMERA variable sent by GET to read files with root privileges and without using access credentials."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2017-9833"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9833, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-9833.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgi-bin/wapopen" ascii nocase
        $param0 = "REFRESH_TIME=Auto_00" ascii nocase
        $param1 = "REFRESH_HTML=auto.htm" ascii nocase
        $param2 = "ONLOAD_HTML=onload.htm" ascii nocase
        $param3 = "STREAMING_HTML=streaming.htm" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
