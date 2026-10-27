// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_vuln_74cms_weixin_sqli {
    meta:
        attack_type = "vuln_74cms_weixin_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "74CMS weixin.php - SQL Injection: There is a libxml_disable_entity_loader function to prevent XML eXternal Entity Injection, but this function needs to be customized by the user. If the user does not customize it, there will be no filtering, which leads to SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/74cms/74cms-weixin-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/plus\/weixin\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])signature=da39a3ee5e6b4b0d3255bfef95601890afd80709(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_afterlogic_path_disclosure {
    meta:
        attack_type = "vuln_afterlogic_path_disclosure"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "AfterLogic Aurora and WebMail Pro < 7.7.9 - Full Path Disclosure: AfterLogic Aurora and WebMail Pro products with 7.7.9 and all lower versions are affected by this vulnerability, simply sending an HTTP DELETE request to WebDAV EndPoint with built-in caldav_public_user@localhost."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/afterlogic-path-disclosure.yaml"
    strings:
        $path0 = /\/dav\/server\.php\/files\/personal\/GIVE_ME_ERROR_TO_GET_DOC_ROOT_2021(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_amazon_ec2_ssrf {
    meta:
        attack_type = "vuln_amazon_ec2_ssrf"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Amazon EC2 - Server-side request forgery (SSRF): SSRF vulnerability exists in Amazon EC2, or Amazon Elastic Compute Cloud which is a web service provided by Amazon Web Services (AWS) that offers resizable compute capacity in the cloud."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/amazon/amazon-ec2-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/latest\/meta-data\/identity-credentials\/ec2\/security-credentials\/ec2-instance(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_apache_nifi_rce {
    meta:
        attack_type = "vuln_apache_nifi_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache NiFi - Remote Code Execution: Apache NiFi is designed for data streaming. It supports highly configurable data routing, transformation, and system mediation logic that indicate graphs. The system has unauthorized remote command execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/apache/apache-nifi-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/nifi-api\/process-groups\/root(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_apache_ofbiz_log4j_rce {
    meta:
        attack_type = "vuln_apache_ofbiz_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache OFBiz - JNDI Remote Code Execution (Apache Log4j): Apache OFBiz is affected by a remote code execution vulnerability in the bundled Apache Log4j logging library. Apache Log4j is vulnerable due to insufficient protections on message lookup substitutions when dealing with."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/apache/apache-ofbiz-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webtools\/control\/main(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_apache_solr_file_read {
    meta:
        attack_type = "vuln_apache_solr_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Solr <=8.8.1 - Local File Inclusion: Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/apache/apache-solr-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/debug\/dump(\/|;|$)/ nocase
        $param0 = /(^|[?&;])stream\.url=file:\/\/\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Windows\/win\.ini(&|$)/ nocase
        $param1 = /(^|[?&;])param=ContentStream(&|$)/ nocase
        $param2 = /(^|[?&;])stream\.url=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_apache_solr_rce {
    meta:
        attack_type = "vuln_apache_solr_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Solr 9.1 - Remote Code Execution: Apache Solr 9.1 is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/apache/apache-solr-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/solr\/gettingstarted_shard1_replica_n1\/config(\/|;|$)/ nocase
        $path1 = /\/solr\/gettingstarted_shard2_replica_n1\/debug\/dump(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_appsmith_info_disclosure {
    meta:
        attack_type = "vuln_appsmith_info_disclosure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Appsmith <= v1.97 - Information Disclosure: Appsmith <= v1.97 instance management API endpoints are accessible without authentication, allowing an attacker to obtain sensitive information such as license plan, instance ID, authentication providers, feature flags, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/appsmith/appsmith-info-disclosure.yaml"
    strings:
        $path0 = /\/api\/v1\/consolidated-api\/view(\/|;|$)/ nocase
        $path1 = /\/api\/v1\/users\/features(\/|;|$)/ nocase
        $path2 = /\/api\/v1\/tenants\/current(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_arangodb_auth_bypass {
    meta:
        attack_type = "vuln_arangodb_auth_bypass"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ArangoDB - Authentication Bypass via URL-Encoded Underscore (%5f) to RCE: ArangoDB <= 3.12.10.1 contains an authentication bypass in the default server.authentication-system-only=true mode (GHSA-rrgq-978q-36mq). The auth gate evaluates the raw URL while action dispatch uses."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/arangodb/arangodb-auth-bypass.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/_db\/_system\/_api\/simple\/first-example(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_avtech_auth_bypass {
    meta:
        attack_type = "vuln_avtech_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AVTECH Video Surveillance Product - Authentication Bypass: AVTECH Video Surveillance Products password disclosure through /cgi-bin/user/Config.cgi."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/avtech/avtech-auth-bypass.yaml"
    strings:
        $param0 = /(^|[?&;])category=Account\.\*(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_avtech_dvr_ssrf {
    meta:
        attack_type = "vuln_avtech_dvr_ssrf"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AVTECH DVR - SSRF: AVTECH DVR device, Search.cgi can be accessed directly. Search.cgi is responsible for searching and accessing cameras in the local network. Search.cgi provides the cgi_query function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/avtech/avtech-dvr-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/cgi-bin\/nobody\/Search\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_avtech_unauth_file_download {
    meta:
        attack_type = "vuln_avtech_unauth_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AVTECH Video Surveillance Product - Unauthenticated File Download: AVTECH video surveillance products unauthenticated file download from web root through /cgi-bin/cgibox, Since the .cab string is verified by the strstr method, the file download can be realized by adding ?.cab."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/avtech/avtech-unauth-file-download.yaml"
    strings:
        $path0 = /\/cgi-bin\/cgibox(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_antsword_backdoor {
    meta:
        attack_type = "vuln_antsword_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AntSword Backdoor Detection: An AntSword application backdoor shell was discovered."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/antsword-backdoor.yaml"
    strings:
        $path0 = /\/\.antproxy\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cisco_implant_detect {
    meta:
        attack_type = "vuln_cisco_implant_detect"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco IOS XE - Impant Detection: Cisco is aware of active exploitation of a previously unknown vulnerability in the web UI feature of Cisco IOS XE Software when exposed to the internet or to untrusted networks. This vulnerability allows a remote, unauthenticated attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/cisco-implant-detect.yaml"
    strings:
        $path0 = /\/webui\/logoutconfirm\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_freepbx_cleanup_backdoor {
    meta:
        attack_type = "vuln_freepbx_cleanup_backdoor"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FreePBX - CVE-2025-57819 Backdoor: FreePBX backdoor cleanup script used in 0-day exploitation of CVE-2025-57819 was detected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/freepbx-cleanup-backdoor.yaml"
    strings:
        $path0 = /\/\.clean\.sh(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jexboss_backdoor {
    meta:
        attack_type = "vuln_jexboss_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JexBoss - Remote Code Execution: JexBoss is susceptible to remote code execution via the webshell. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/jexboss-backdoor.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/jexws\/jexws\.jsp(\/|;|$)/ nocase
        $path1 = /\/jexws4\/jexws4\.jsp(\/|;|$)/ nocase
        $path2 = /\/jexinv4\/jexinv4\.jsp(\/|;|$)/ nocase
        $path3 = /\/jbossass\/jbossass\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kevinlab_hems_backdoor {
    meta:
        attack_type = "vuln_kevinlab_hems_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "KevinLAB HEMS - Backdoor Detection: KevinLAB HEMS has an undocumented backdoor account and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/kevinlab-hems-backdoor.yaml"
    strings:
        $param0 = /(^|[?&;])userid=kevinlab(&|$)/ nocase
        $param1 = /(^|[?&;])userpass=kevin003(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_maccmsv10_backdoor {
    meta:
        attack_type = "vuln_maccmsv10_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Maccmsv10 - Backdoor Remote Code Execution: Maccmsv10 contains a backdoor which can be exploited by remote attackers. The backdoor is accessible via the '/index.php/bbs/index/download' endpoint and the special 'getpwd' parameter value of 'WorldFilledWithLove'. Exploitation of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/maccmsv10-backdoor.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])getpwd=WorldFilledWithLove(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sap_netweaver_backdoor {
    meta:
        attack_type = "vuln_sap_netweaver_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SAP NetWeaver - Backdoor Detection: Detected a potential backdoor in SAP NetWeaver allowing unauthorized command execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/sap-netweaver-backdoor.yaml"
    strings:
        $path0 = /\/irj\/helper\.jsp(\/|;|$)/ nocase
        $path1 = /\/irj\/cache\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sharepoint_toolshell_backdoor {
    meta:
        attack_type = "vuln_sharepoint_toolshell_backdoor"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SharePoint Webshell - ToolShell: Detects a persistent webshell named 'spinstall0.aspx' deployed on Microsoft SharePoint servers. This file exposes sensitive cryptographic machineKey values from the SharePoint configuration, indicating the presence of a ToolShell backdoor."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/backdoor/sharepoint-toolshell-backdoor.yaml"
    strings:
        $path0 = /\/_layouts\/15\/spinstall0\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_bentoml_ssrf {
    meta:
        attack_type = "vuln_bentoml_ssrf"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bentoml - Server Side Request Forgery: BentoML's upload file request is vulnerable to SSRF that allowing attacker to access internal service (local network)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/bentoml-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/encode_image(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_crm_sqli {
    meta:
        attack_type = "vuln_chanjet_crm_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chanjet CRM - SQL Injection: SQL injection exists in the Chanjet CRM get_usedspace.php, and sensitive information can be obtained through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/chanjet-tplus/chanjet-crm-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/webservice\/get_usedspace\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_tplus_unauth_passreset {
    meta:
        attack_type = "vuln_chanjet_tplus_unauth_passreset"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chanjet Tplus - Unauthorized Password Reset: There is an unauthorized administrator password modification vulnerability in UF Chanjet T+ RecoverPassword.aspx. An attacker can use this vulnerability to modify the administrator account password to log in to the backend."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/chanjet-tplus/chanjet-tplus-unauth-passreset.yaml"
    strings:
        $path0 = /\/tplus\/ajaxpro\/RecoverPassword,App_Web_recoverpassword\.aspx\.cdcab7d2\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=SetNewPwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_cisco_broadworks_log4j_rce {
    meta:
        attack_type = "vuln_cisco_broadworks_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco BroadWorks - Remote Code Execution (Apache Log4j): Cisco BroadWorks is susceptible to Log4j JNDI remote code execution. Cisco BroadWorks is an enterprise-grade calling and collaboration platform delivering unmatched performance, security and scale."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/cisco/cisco-broadworks-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/commpilot\/servlet\/Login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cisco_ucm_cluster_enum {
    meta:
        attack_type = "vuln_cisco_ucm_cluster_enum"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Cisco Unified Communications Manager - Cluster Enumeration: Enumerated Cisco UCM cluster nodes (servers) using the unauthenticated UDS API (XML), allowing identification of backend servers without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/cisco/cisco-ucm-cluster-enum.yaml"
    strings:
        $path0 = /\/cucm-uds\/servers(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cisco_unified_communications_log4j_rce {
    meta:
        attack_type = "vuln_cisco_unified_communications_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco Unified Communications - Remote Code Execution (Apache Log4j): Cisco Unified Communications is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/cisco/cisco-unified-communications-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ccmadmin\/j_security_check(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cisco_webex_log4j_rce {
    meta:
        attack_type = "vuln_cisco_webex_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco WebEx - Remote Code Execution (Apache Log4j): Cisco WebEx is susceptible to Log4j JNDI remote code execution. Cisco WebEx provides web conferencing, videoconferencing and contact center as a service applications."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/cisco/cisco-webex-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/orion\/login(\/|;|$)/ nocase
        $param0 = /(^|[?&;])siteurl=meet(&|$)/ nocase
        $param1 = /(^|[?&;])type=getFailureTimes(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_code42_log4j_rce {
    meta:
        attack_type = "vuln_code42_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Code42 - Remote Code Execution (Apache Log4j): Multiple Code42 components are impacted by the logj4 vulnerability. Affected Code42 components include: - Code42 cloud: Updated Log4j from 2.15.0 to 2.17.1 on January 26, 2022 - Code42 app for Incydr Basic and Advanced and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/code42/code42-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/c42api\/v3\/LoginConfiguration(\/|;|$)/ nocase
        $param0 = /(^|[?&;])url=https:\/\/localhost(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_concrete_xss {
    meta:
        attack_type = "vuln_concrete_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Concrete CMS <8.5.2 - Cross-Site Scripting: Concrete CMS before 8.5.2 contains a cross-site scripting vulnerability in preview_as_user function using cID parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/concrete/concrete-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ccm\/system\/panels\/page\/preview_as_user\/preview(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_confluence_xslt_macro_ssrf {
    meta:
        attack_type = "vuln_confluence_xslt_macro_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Atlassian Confluence XSLT Macro - Server-Side Request Forgery: Atlassian Confluence Data Center and Server include an XSLT macro feature that may be vulnerable to Server-Side Request Forgery (SSRF). By leveraging the ability of the XSLT macro to access external resources."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/confluence-xslt-macro-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/rest\/api\/content\/macro\/preview(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cpanel_mailman_xss {
    meta:
        attack_type = "vuln_cpanel_mailman_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "cPanel Mailman - Cross-Site Scripting: cPanel Mailman listinfo reflects the `mpidentity` query parameter into the HTML response without proper output encoding, resulting in reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/cpanel/cpanel-mailman-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mailman\/listinfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dahua_bitmap_fileupload {
    meta:
        attack_type = "vuln_dahua_bitmap_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua Bitmap - File Upload Remote Code Execution"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dahua/dahua-bitmap-fileupload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/emap\/webservice\/gis\/soap\/bitmap(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dahua_icc_backdoor_user {
    meta:
        attack_type = "vuln_dahua_icc_backdoor_user"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dahua Intelligent IoT - Information Disclosure: There is a vulnerability in the user login interface /evo-apigw/evo-oauth/oauth/token of Zhejiang Dahua Technology Co., Ltd. Intelligent IoT Integrated Management Platform. Users can successfully log in to the platform using."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dahua/dahua-icc-backdoor-user.yaml"
    strings:
        $path0 = /\/evo-apigw\/evo-oauth\/oauth\/token(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dahua_icc_getclassvalue_rce {
    meta:
        attack_type = "vuln_dahua_icc_getclassvalue_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua 'GetClassValue' - Remote Code Execution: Remote Code Execution Vulnerability in Dahua Intelligent IoT Integrated Management Platform via GetClassValue.jsp."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dahua/dahua-icc-getclassvalue-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/evo-apigw\/admin\/API\/Developer\/GetClassValue\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dahua_wpms_lfi {
    meta:
        attack_type = "vuln_dahua_wpms_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dahua Smart Park Management Platform - Arbitary File Read: Dahua Smart Park Management Platform is vulnerable to Local File Inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dahua/dahua-wpms-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/portal\/itc\/attachment_downloadByUrlAtt\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dahua_wpms_rce {
    meta:
        attack_type = "vuln_dahua_wpms_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua Smart Park Integrated Management Platform - Remote Command Execution: Dahua Smart Park Integrated Management Platform is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dahua/dahua-wpms-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/CardSolution\/card\/accessControl\/swingCardRecord\/deleteFtp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dedecms_carbuyaction_fileinclude {
    meta:
        attack_type = "vuln_dedecms_carbuyaction_fileinclude"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DedeCmsV5.6 Carbuyaction Fileinclude: A vulnerability in DedeCMS's 'carbuyaction.php' endpoint allows remote attackers to return the content of locally stored files via a vulnerability in the 'code' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-carbuyaction-fileinclude.yaml"
    strings:
        $path0 = /\/plus\/carbuyaction\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dopost=return(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_dedecms_config_xss {
    meta:
        attack_type = "vuln_dedecms_config_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DedeCMS 5.7 - Cross-Site Scripting: DeDeCMS 5.7 contains a cross-site scripting vulnerability in the '/include/dialog/config.php' file. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-config-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/include\/dialog\/config\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dedecms_membergroup_sqli {
    meta:
        attack_type = "vuln_dedecms_membergroup_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dede CMS - SQL Injection: Dede CMS contains a SQL injection vulnerability which allows remote unauthenticated users to inject arbitrary SQL statements via the ajax_membergroup.php endpoint and the membergroup parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-membergroup-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/member\/ajax_membergroup\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dedecms_rce {
    meta:
        attack_type = "vuln_dedecms_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DedeCMS 5.8.1-beta - Remote Code Execution: DedeCMS 5.8.1-beta is susceptible to remote code execution via a variable override vulnerability that allows an attacker to construct malicious code with template file inclusion without proper authorization, thus possibly obtaining."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/plus\/flink\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_deos_open500ems_panel {
    meta:
        attack_type = "vuln_deos_open500ems_panel"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DEOS OPEN 500EMS Controller - Admin Exposure: The DEOS OPEN 500EMS controller exposes administrative functions without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/deos-open500-admin.yaml"
    strings:
        $path0 = /\/cgi-bin\/cosmobdf\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dify_ssrf_remote_upload {
    meta:
        attack_type = "vuln_dify_ssrf_remote_upload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dify < 1.13.0 - Unauthenticated SSRF via Remote File Upload: Detected Dify prior to 1.13.0 is vulnerable to unauthenticated Server-Side Request Forgery via the /console/api/remote-files/upload endpoint. The endpoint accepted a user-controlled URL parameter and issued HTTP."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dify/dify-ssrf-remote-upload.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/console\/api\/remote-files\/upload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dlink_netgear_xss {
    meta:
        attack_type = "vuln_dlink_netgear_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Dlink DSR-250 and Netgear Prosafe - Cross-Site Scripting: Dlink DSR-250 and Netgear Prosafe are vulnerable to reflected cross site scripting endpoint scgi-bin/platform.cgi in parameter SSLVPN."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dlink/dlink-netgear-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=portalLogin\.htm(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_drupal_avatar_xss {
    meta:
        attack_type = "vuln_drupal_avatar_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Drupal Avatar Uploader - Cross-Site Scripting: Drupal Avatar Uploader v7.x-1.0-beta8 plugin contains a cross-site scripting vulnerability in the slider import search feature and tab parameter via plugin settings."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/drupal/drupal-avatar-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/avatar_uploader\.pages\.inc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_drupal7_elfinder_rce {
    meta:
        attack_type = "vuln_drupal7_elfinder_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Drupal 7 Elfinder - Remote Code Execution: Identifies Drupal sites with the elfinder library installed, which could be vulnerable to unrestricted file upload through the connector.php file.When this component is detected, the site may be vulnerable to remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/drupal/drupal7-elfinder-rce.yaml"
    strings:
        $path0 = /\/sites\/all\/libraries\/elfinder\/connectors\/php\/connector\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_esafenet_mysql_fileread {
    meta:
        attack_type = "vuln_esafenet_mysql_fileread"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Esafenet CDG mysql - File Read: CDGServer3 Unauthorized File Download vulnerability is detected."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/esafenet/esafenet-mysql-fileread.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/CDGServer3\/SQL\/MYSQL\/create_SmartSec_mysql\.sql(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_esafenet_netsecconfigajax_sqli {
    meta:
        attack_type = "vuln_esafenet_netsecconfigajax_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Esafenet CDG NetSecConfigAjax - Sql Injection: The `state` parameter of the `NetSecConfigAjax` interface of the Yisaitong electronic document security management system does not pre-compile and adequately verify the incoming data, resulting in a SQL injection vulnerability in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/esafenet/esafenet-netsecconfigajax-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/CDGServer3\/NetSecConfigAjax;Service(\/|;|$)/ nocase
        $param0 = /(^|[?&;])command=updateNetSec(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_esafenet_noticeajax_sqli {
    meta:
        attack_type = "vuln_esafenet_noticeajax_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Esafenet CDG NoticeAjax - Sql Injection: CDGServer3 NoticeAjax Interface Sql Injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/esafenet/esafenet-noticeajax-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])command=delNotice(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_feiyuxing_ent_router_infoleak {
    meta:
        attack_type = "vuln_feiyuxing_ent_router_infoleak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FeiYuXing Enterprise Router - Information Leakage: The FeiYuXing Enterprise Router Information Leakage Vulnerability is a critical flaw that allows unauthorized attackers to retrieve sensitive configuration details from the router."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/feiyuxing/feiyuxing-ent-router-infoleak.yaml"
    strings:
        $path0 = /\/js\/\.\.\/\.htpasswd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_fine_report_v9_file_upload {
    meta:
        attack_type = "vuln_fine_report_v9_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FineReport v9 Arbitrary File Overwrite: FineReport ( A business intelligence (BI) and reporting software ) is vulnerable to Arbitrary File Overwrite."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/finereport/fine-report-v9-file-upload.yaml"
    strings:
        $path0 = "/WebReport/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_finereport_path_traversal {
    meta:
        attack_type = "vuln_finereport_path_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FineReport 8.0 - Local File Inclusion: FIneReport 8.0 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/finereport/finereport-path-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/report\/ReportServer(\/|;|$)/ nocase
        $param0 = /(^|[?&;])resourcepath=privilege\.xml(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_finereport_sqli_rce {
    meta:
        attack_type = "vuln_finereport_sqli_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FineReport SQLi - Remote Code Execution: Access URL:/webroot/decision/view/ReportServer?test=&n=, which can execute the SQL statement in GET parameter n. This vulnerability is caused by Fanruan's own sqlite-jdbc-x.x.x.x.jar driver."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/finereport/finereport-sqli-rce.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/webroot\/decision\/view\/ReportServer(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_fronsetiav_xss {
    meta:
        attack_type = "vuln_fronsetiav_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Fronsetiav1.1 - Cross-Site Scripting: The fronsetiav1.1 application is vulnerable to a Reflected XSS attack through the show_operations.jsp endpoint. An attacker can inject malicious scripts via the WSDL Location input, which is executed in the victim's browser due to improper."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/fronsetiav-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/show_operations\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_froxlor_xss {
    meta:
        attack_type = "vuln_froxlor_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Froxlor Server Management - Cross-Site Scripting: Froxlor Server Management is susceptible to cross-site scripting via clicking the forgot password link. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/froxlor-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/index\.php\/javascript&colon;alert\(document\.domain\);dd&sol;&sol;(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_xmlrpc_pingback_ssrf {
    meta:
        attack_type = "vuln_xmlrpc_pingback_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XMLRPC Pingback SSRF: XMLRPC Pingback leads to SSRF."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/xmlrpc-pingback-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/xmlrpc\/pingback(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_gestsup_account_takeover {
    meta:
        attack_type = "vuln_gestsup_account_takeover"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GestSup - Account Takeover: GestSup contains an authentication bypass vulnerability allowing attackers to take over user accounts, leading to full compromise including data disclosure and modification."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/gestsup-account-takeover.yaml"
    strings:
        $path0 = /\/ajax\/ticket_user_db\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_gestsup_xss {
    meta:
        attack_type = "vuln_gestsup_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GestSup - Cross-Site Scripting: GestSup allows its users to add events to the calendar of all users. This is the HTTP request sent when a user adds an event to their calendar."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/gestsup-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ajax\/calendar\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])page=calendar(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_gitea_rce {
    meta:
        attack_type = "vuln_gitea_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gitea 1.4.0 - Remote Code Execution: Gitea 1.4.0 is vulnerable to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/gitea/gitea-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = ".git/info/lfs/objects" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_glpi_planning_user_enum {
    meta:
        attack_type = "vuln_glpi_planning_user_enum"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GLPI Planning - Unauthenticated Username Enumeration: GLPI exposes the check availability planning view at front/planning.php without authentication when the genical parameter is set, allowing unauthenticated attackers to enumerate user display names by iterating users_id in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/glpi/glpi-planning-user-enum.yaml"
    strings:
        $path0 = /\/front\/planning\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])begin=2000-01-01(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_gnuboard_sms_xss {
    meta:
        attack_type = "vuln_gnuboard_sms_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gnuboard CMS - Cross-Site Scripting: Gnuboard CMS contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary JavaScript into the responses returned by the server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/gnuboard/gnuboard-sms-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugin\/sms5\/ajax\.sms_emoticon\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_gradio_lfi {
    meta:
        attack_type = "vuln_gradio_lfi"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gradio - Local File Inclusion: Gradio's Dropdown component is vulnerable to Local File Inclusion (LFI) when the value is a dictionary controlled by an attacker. In the postprocess of components, if the value type is a dict, it flows to the async_move_files_to_cache function.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/gradio-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/run\/predict(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_harman_media_suite_lfi {
    meta:
        attack_type = "vuln_harman_media_suite_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Harman Media Suite <= 4.2.0 - Local File Disclosure: Harman Media Suite (versions 4.2.0 and below) are vulnerable to possible Local File Disclosure. This allows an unauthenticated user to potentially download attachments and recordings stored within the Media Suite application."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/harman-media-suite-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/userportal/api/rest/contentChannels/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hcm_cloud_lfi {
    meta:
        attack_type = "vuln_hcm_cloud_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HCM Cloud - Arbitrary File Read: HCM-Cloud professional human resources platform in the cloud download Arbitrary file read vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hcm/hcm-cloud-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/model_report\/file\/download(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hikvision_isecure_info_leak {
    meta:
        attack_type = "vuln_hikvision_isecure_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HIKVISION iSecure Center - Information Leak: HIKVISION iSecure Center comprehensive security management platform is an 'integrated' and 'intelligent' platform. By accessing equipment such as video surveillance, all-in-one card, parking lot, alarm detection and other systems."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hikvision/hikvision-isecure-info-leak.yaml"
    strings:
        $path0 = /\/portal\/conf\/config\.properties(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hikvision_ivms_file_upload_bypass {
    meta:
        attack_type = "vuln_hikvision_ivms_file_upload_bypass"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hikvison iVMS - File Upload Bypass: Hikvision iVMS integrated security system has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability by obtaining the encryption key to create a forged token. By using the forged token, they can make."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hikvision/hikvision-ivms-file-upload-bypass.yaml"
    strings:
        $path0 = /\/eps\/api\/resourceOperations\/upload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hikvision_ivms_file_upload_rce {
    meta:
        attack_type = "vuln_hikvision_ivms_file_upload_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hikvision iVMS-8700 - File Upload Remote Code Execution: Arbitrary file upload vulnerability in HIKVISION iVMS-8700 Integrated Security Management Platform Software allows attackers to upload and execute malicious files, leading to potential unauthorized server control."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hikvision/hikvision-ivms-file-upload-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/eps\/resourceOperations\/upload\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hikvision_js_files_upload {
    meta:
        attack_type = "vuln_hikvision_js_files_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hikvision iSecure Center - File Upload: THikvision iSecure Center /center/api/files;.js has an arbitrary file upload vulnerability"
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hikvision/hikvision-js-files-upload.yaml"
    strings:
        $path0 = "/clusterMgr/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hjsoft_hcm_lfi {
    meta:
        attack_type = "vuln_hjsoft_hcm_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongjing HCM - Local File Inclusion: There is an arbitrary file read vulnerability in the Hongjing eHR /DownLoadCourseware interface. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hjsoft/hjsoft-hcm-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/w_selfservice\/oauthservlet\/\.\.\/\.\.\/DownLoadCourseware(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hjsoft_hcm_sqli {
    meta:
        attack_type = "vuln_hjsoft_hcm_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongjing HCM - Sql Injection: There is a SQL injection vulnerability in the /servlet/sduty/getSdutyTree interface of Hongjing HCM. Unauthenticated remote attackers can execute arbitrary commands by exploiting the SQL injection vulnerability with the database xp_cmdshell."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/hjsoft/hjsoft-hcm-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/w_selfservice\/oauthservlet\/\.\.\/\.\.\/servlet\/sduty\/getSdutyTree(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_httpbin_xss {
    meta:
        attack_type = "vuln_httpbin_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HTTPBin - Cross-Site Scripting: HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/httpbin/httpbin-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/base64\/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ\+(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_huawei_authhttp_lfi {
    meta:
        attack_type = "vuln_huawei_authhttp_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Huawei Auth Http Server - Arbitrary File Read: Huawei Auth HTTP Server is vulnerable to Arbitrary File Read."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/huawei/huawei-authhttp-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/umweb\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_idocview_2word_fileupload {
    meta:
        attack_type = "vuln_idocview_2word_fileupload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IDoc View /html/2word - Arbitrary File Upload"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/idoc/idocview-2word-fileupload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/html\/2word(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_imo_file_download {
    meta:
        attack_type = "vuln_imo_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IMO - Arbitrary File Download: The imo cloud office can read system sensitive files because the filename parameter of the /file/Placard/upload/Imo_DownLoadUI.php page is not strictly filtered."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/imo/imo-file-download.yaml"
    strings:
        $path0 = /\/file\/Placard\/upload\/Imo_DownLoadUI\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])filename=\/OpenPlatform\/config\/kdBind\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_imo_rce {
    meta:
        attack_type = "vuln_imo_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "IMO - Remote Code Execution: The lax filtering of imo cloud office/file/NDisk/get_file.php allows unlimited file uploads. Attackers can directly obtain website permissions through this vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/imo/imo-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/file\/NDisk\/get_file\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_infinitt_pacs_file_upload {
    meta:
        attack_type = "vuln_infinitt_pacs_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Infinitt PACS System - Arbitary File Upload: Infinitt PACS System is vulnerable to file upload vulnerability which allows an attacker to upload a webshell and gain unauthorized access to the server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/infinitt/infinitt-pacs-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webservices\/WebJobUpload\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_infinitt_pacs_info_disclosure {
    meta:
        attack_type = "vuln_infinitt_pacs_info_disclosure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Infinitt PACS System - Information Disclosure: Infinitt PACS System is vulnerable to an Information Disclosure vulnerability. By sending a crafted request, an attacker can obtain sensitive user information, including passwords."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/infinitt/infinitt-pacs-info-leak.yaml"
    strings:
        $path0 = /\/webservices\/WebUserLogin\.asmx\/GetUserInfoByUserID(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_infoblox_netmri_rails_cookie_rce {
    meta:
        attack_type = "vuln_infoblox_netmri_rails_cookie_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Infoblox NetMRI < 7.6.1 - Remote Code Execution via Hardcoded Ruby Cookie Secret Key: Infoblox NetMRI virtual appliances before version 7.6.1 are vulnerable to remote code execution (RCE) due to the use of a hardcoded Ruby on Rails session cookie secret key. The Rails web."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/infoblox/infoblox-netmri-rails-cookie-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webui\/gui_states\/index\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jenkins_async_people {
    meta:
        attack_type = "vuln_jenkins_async_people"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jenkins panel async-people"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jenkins/jenkins-asyncpeople.yaml"
    strings:
        $path0 = "/asynchPeople/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jenkins_script {
    meta:
        attack_type = "vuln_jenkins_script"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jenkins - Remote Code Execution: Jenkins is susceptible to a remote code execution vulnerability due to accessible script functionality."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jenkins/jenkins-script.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/jenkins\/script(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jenkins_stack_trace {
    meta:
        attack_type = "vuln_jenkins_stack_trace"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Detect Jenkins in Debug Mode with Stack Traces Enabled: Module identified that the affected host is running an instance of Jenkins in debug mode, as a result stack traces are enabled."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jenkins/jenkins-stack-trace.yaml"
    strings:
        $path0 = "/adjuncts/3a890183/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jinhe_jc6_sqli {
    meta:
        attack_type = "vuln_jinhe_jc6_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jinhe OA - SQL Injection: SQL injection vulnerability in the ljc6/servlet/clobfield interface of Jinhe OA jc6. An attacker can obtain sensitive information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jinhe/jinhe-jc6-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/jc6\/servlet\/clobfield(\/|;|$)/ nocase
        $param0 = /(^|[?&;])key=readClob(&|$)/ nocase
        $param1 = /(^|[?&;])sImgname=filename(&|$)/ nocase
        $param2 = /(^|[?&;])sTablename=FC_ATTACH(&|$)/ nocase
        $param3 = /(^|[?&;])sKeyname=djbh(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jinhe_oa_c6_lfi {
    meta:
        attack_type = "vuln_jinhe_oa_c6_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jinhe OA C6 download.jsp - Arbitary File Read: There is an arbitrary file read vulnerability in Jinhe OA C6 download.jsp file, through which an attacker can obtain sensitive information in the server"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jinhe/jinhe-oa-c6-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/C6\/Jhsoft\.Web\.module\/testbill\/dj\/download\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jinhe_oa_c6_upload_lfi {
    meta:
        attack_type = "vuln_jinhe_oa_c6_upload_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jinhe OA_C6_UploadFileDownLoadnew - Arbitrary File Read: There is an arbitrary file reading vulnerability in the UploadFileDownLoadnew.aspx interface of Jinhe OA C6. An unauthenticated attacker can use this vulnerability to read important system files (such as database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jinhe/jinhe-oa-c6-upload-lfi.yaml"
    strings:
        $path0 = "/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/" ascii nocase
        $param0 = /(^|[?&;])FilePath=\.\.\/Resource\/JHFileConfig\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jira_https_mode_open_redirect {
    meta:
        attack_type = "vuln_jira_https_mode_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JIRA in HTTPS mode - Open Redirect: Detected Open redirect vulnerability in Jira via os_destination parameter versions 5.2.11, 6.2, and 6.2.2."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-https-mode-open-redirect.yaml"
    strings:
        $path0 = /\/ThisCanBeAnything(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_servicedesk_signup {
    meta:
        attack_type = "vuln_jira_servicedesk_signup"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Jira Service Desk Signup: This instance of Atlassian JIRA is misconfigured to allow an attacker to sign up (create a new account) just by navigating to the signup page that is accessible at the URL /servicedesk/customer/user/signup. After the attacker has created a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-servicedesk-signup.yaml"
    strings:
        $path0 = /\/servicedesk\/customer\/user\/signup(\/|;|$)/ nocase
        $path1 = /\/secure\/Signup!default\.jspa(\/|;|$)/ nocase
        $path2 = /\/secure\/Signup\.jspa(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_installed_gadgets {
    meta:
        attack_type = "vuln_jira_unauthenticated_installed_gadgets"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated Installed gadgets: Some Jira instances allow to read the installed gadgets (sometimes it's also possible to read config xml file for some gadgets)"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-installed-gadgets.yaml"
    strings:
        $path0 = /\/rest\/config\/1\.0\/directory(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_projectcategories {
    meta:
        attack_type = "vuln_jira_unauthenticated_projectcategories"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated Project Categories"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-projectcategories.yaml"
    strings:
        $path0 = /\/rest\/api\/2\/projectCategory(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_projects {
    meta:
        attack_type = "vuln_jira_unauthenticated_projects"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated Projects"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-projects.yaml"
    strings:
        $path0 = /\/rest\/api\/2\/project(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_resolutions {
    meta:
        attack_type = "vuln_jira_unauthenticated_resolutions"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated Resolutions"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-resolutions.yaml"
    strings:
        $path0 = /\/rest\/api\/2\/resolution(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_screens {
    meta:
        attack_type = "vuln_jira_unauthenticated_screens"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated Access to screens"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-screens.yaml"
    strings:
        $path0 = /\/rest\/api\/2\/screens(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jira_unauthenticated_user_picker {
    meta:
        attack_type = "vuln_jira_unauthenticated_user_picker"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Jira Unauthenticated User Picker"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jira/jira-unauthenticated-user-picker.yaml"
    strings:
        $path0 = /\/secure\/popups\/UserPickerBrowser\.jspa(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jolokia_file_read_compilerdirectivesadd {
    meta:
        attack_type = "vuln_jolokia_file_read_compilerdirectivesadd"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jolokia - CompilerDirectivesAdd File Read: Jolokia is vulnerable to local file inclusion via compilerDirectivesAdd."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jolokia/jolokia-file-read-compilerdirectivesadd.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/jolokia\/exec\/com\.sun\.management:type=DiagnosticCommand\/compilerDirectivesAdd\/!\/etc!\/passwd(\/|;|$)/ nocase
        $path1 = /\/actuator\/jolokia\/exec\/com\.sun\.management:type=DiagnosticCommand\/compilerDirectivesAdd\/!\/etc!\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jolokia_tomcat_creds_leak {
    meta:
        attack_type = "vuln_jolokia_tomcat_creds_leak"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jolokia <= 1.7.1 Information Leakage: Tomcat's credential disclosure leading to Remote Code Execution via WAR upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jolokia/jolokia-tomcat-creds-leak.yaml"
    strings:
        $path0 = /\/jolokia\/read\/Users:database=UserDatabase,type=UserDatabase(\/|;|$)/ nocase
        $path1 = /\/actuator\/jolokia\/read\/Users:database=UserDatabase,type=UserDatabase(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_joomla_com_booking_component {
    meta:
        attack_type = "vuln_joomla_com_booking_component"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! com_booking component 2.4.9 - Information Leak: Joomla! com_booking component suffers from Information leak vulnerability in which sensitive or confidential data is unintentionally exposed or made accessible to unauthorized individuals or systems."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-com-booking-component.yaml"
    strings:
        $param0 = /(^|[?&;])option=com_booking(&|$)/ nocase
        $param1 = /(^|[?&;])controller=customer(&|$)/ nocase
        $param2 = /(^|[?&;])task=getUserData(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_com_fabrik_lfi {
    meta:
        attack_type = "vuln_joomla_com_fabrik_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! com_fabrik 3.9.11 - Local File Inclusion: Joomla! com_fabrik 3.9.11 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-com-fabrik-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])task=plugin\.pluginAjax(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_department_sqli {
    meta:
        attack_type = "vuln_joomla_department_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla `departments` - SQL Injection: Joomla! `com_departments` parameter contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-department-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])option=com_departments(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_easyshop_lfi {
    meta:
        attack_type = "vuln_joomla_easyshop_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component Easy Shop 1.2.3 - Local File Inclusion: The Joomla! component Easy Shop version 1.2.3 is vulnerable to Local File Inclusion (LFI) attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-easyshop-lfi.yaml"
    strings:
        $param0 = /(^|[?&;])option=com_easyshop(&|$)/ nocase
        $param1 = /(^|[?&;])task=ajax\.loadImage(&|$)/ nocase
        $param2 = /(^|[?&;])file=Li4vLi4vY29uZmlndXJhdGlvbi5waHA=(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_iproperty_xss {
    meta:
        attack_type = "vuln_joomla_iproperty_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla iProperty Real Estate 4.1.1 - Cross-Site Scripting: Joomla extension iproperty is vulnerable to XSS in GET parameter 'filter_keyword'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-iproperty-real-estate-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/iproperty\/property-views\/all-properties-with-map(\/|;|$)/ nocase
        $param0 = /(^|[?&;])option=com_iproperty(&|$)/ nocase
        $param1 = /(^|[?&;])view=allproperties(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_joombri_careers_xss {
    meta:
        attack_type = "vuln_joomla_joombri_careers_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla JoomBri Careers 3.3.0 - Cross-Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-joombri-careers-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/for-jobseekers\/search-jobs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_joomla_jvehicles_lfi {
    meta:
        attack_type = "vuln_joomla_jvehicles_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component com_sef - Local File Inclusion: A local file inclusion vulnerability in the Jvehicles (com_jvehicles) component version 1.0 for Joomla! allows remote attackers to load arbitrary files via the controller parameter in index.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-jvehicles-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])option=com_jvehicles(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_joomla_jvtwitter_xss {
    meta:
        attack_type = "vuln_joomla_jvtwitter_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla JVTwitter - Cross-Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-jvtwitter-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/modules\/mod_jvtwitter\/jvtwitter\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_joomla_solidres_xss {
    meta:
        attack_type = "vuln_joomla_solidres_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla Solidres 2.13.3 - Cross-Site Scripting: Joomla extension for Solidres - Online Booking System & Reservation Software is vulnerable to XSS in GET parameter 'show'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/joomla/joomla-solidres-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/joomla\/greenery_hub\/index\.php\/en\/hotels\/reservations(\/|;|$)/ nocase
        $param0 = /(^|[?&;])location=d2tff(&|$)/ nocase
        $param1 = /(^|[?&;])ordering=score(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jupyter_notebook_rce {
    meta:
        attack_type = "vuln_jupyter_notebook_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jupyter Notebook - Remote Command Execution: Jupyter Notebook is an interactive Notebook, computer application is a web based visualization, Jupyter Notebook API/terminals path there are loopholes in the remote command execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/jupyter-notebook-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/terminals(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_landray_eis_sqli {
    meta:
        attack_type = "vuln_landray_eis_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Landray EIS - SQL Injection: Landray's smart collaboration platform EIS has a very rich collection of modules to meet the needs of organizations and enterprises in knowledge, collaboration, and project management system construction. There is a SQL injection vulnerability in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/landray/landray-eis-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/SM\/rpt_listreport_definefield\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_landray_eis_ws_infoleak {
    meta:
        attack_type = "vuln_landray_eis_ws_infoleak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Landray EIS WS_getAllInfos - Information Disclosure: Landray EIS WS_getAllInfos interface suffers from a sensitive information disclosure vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/landray/landray-eis-ws-infoleak.yaml"
    strings:
        $path0 = /\/WS\/Basic\/Basic\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_landray_oa_replaceextend_rce {
    meta:
        attack_type = "vuln_landray_oa_replaceextend_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Landray OA replaceExtend Function - Remote Code Execution: There is a remote command execution vulnerability in Lanling OA replaceExtend Method. Use This Method To Move dataxml.jsp To A Dirctory That Can Access Without Auth,Then An attacker can Run Command With this."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/landray/landray-oa-replaceextend-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/resource\/help\/sys\/portal\/dataxml\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_landray_oa_treexml_rce {
    meta:
        attack_type = "vuln_landray_oa_treexml_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Landray OA Treexml.tmpl - Remote Code Execution: There is a remote command execution vulnerability in Lanling OA treexml.tmpl. An attacker can obtain server permissions by sending a specific request package."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/landray/landray-oa-treexml-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/data\/sys-common\/treexml\.tmpl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_leantime_stored_xss {
    meta:
        attack_type = "vuln_leantime_stored_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Leantime < 3.3 = Cross-Site Scripting: Any low privileged user like manager, or editor, can create an API key with XSS payload. When admin will visit the Company page, the XSS will automatically get triggerred leading to the unauthorized action performed from the ADMIN account.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/leantime/leantime-stored-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/newApiKey(\/|;|$)/ nocase
        $path1 = "/setting/editCompanySettings/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_lg_nas_rce {
    meta:
        attack_type = "vuln_lg_nas_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LG NAS Devices - Remote Code Execution: LG NAS devices contain a pre-auth remote command injection via the 'password' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/lg-nas-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/system\/sharedir\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_limesurvey_open_redirect {
    meta:
        attack_type = "vuln_limesurvey_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LimeSurvey - Open Redirect via editorLink: LimeSurvey before 6.16.11 contains an open redirect vulnerability in the editorLink route. An attacker can craft a URL that redirects users to an arbitrary external site, potentially enabling phishing attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/limesurvey/limesurvey-open-redirect.yaml"
    strings:
        $param0 = /(^|[?&;])r=editorLink(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_magento_2_exposed_api {
    meta:
        attack_type = "vuln_magento_2_exposed_api"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Exposed Magento 2 API: The API in Magento 2 can be accessed by the world without providing credentials. Through the API information like storefront, (hidden) products including prices are exposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/magento/magento-2-exposed-api.yaml"
    strings:
        $path0 = /\/rest\/V1\/products(\/|;|$)/ nocase
        $path1 = /\/rest\/V1\/store\/storeConfigs(\/|;|$)/ nocase
        $path2 = /\/rest\/V1\/store\/storeViews(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_magento_downloader_fpd {
    meta:
        attack_type = "vuln_magento_downloader_fpd"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Magento Downloader - Full Path Disclosure: Detected Magento Downloader component exposed internal file system paths through direct file access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/magento/magento-downloader-fpd.yaml"
    strings:
        $path0 = /\/downloader\/lib\/Mage\/Backup\/Nomedia\.php(\/|;|$)/ nocase
        $path1 = /\/downloader\/lib\/Mage\/Archive\/Tar\.php(\/|;|$)/ nocase
        $path2 = /\/downloader\/lib\/Mage\/Archive\/Gz\.php(\/|;|$)/ nocase
        $path3 = /\/downloader\/lib\/Mage\/Archive\/Bz\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_magento_polyshell_rce {
    meta:
        attack_type = "vuln_magento_polyshell_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Magento PolyShell Unauthenticated File Upload to RCE: Magento lacks file type validation on custom product options file upload feature accessible via unauthenticated REST/GraphQL APIs. Attackers can upload arbitrary PHP files through guest cart endpoints without authentication.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/magento/magento-polyshell-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/rest\/default\/V1\/guest-carts(\/|;|$)/ nocase
        $path1 = "/pub/media/custom_options/quote/" ascii nocase
        $path2 = "/media/custom_options/quote/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_magento_unprotected_dev_files {
    meta:
        attack_type = "vuln_magento_unprotected_dev_files"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Magento Unprotected development files: Magento version 1.9.2.x includes /dev directories or files that might reveal your passwords and other sensitive information. The /dev directories and files are not protected by default. According to Magento, 'these tests are not supposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/magento/magento-unprotected-dev-files.yaml"
    strings:
        $path0 = /\/dev\/tests\/functional\/credentials\.xml\.dist(\/|;|$)/ nocase
        $path1 = /\/dev\/tests\/functional\/etc\/config\.xml\.dist(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_metersphere_plugin_rce {
    meta:
        attack_type = "vuln_metersphere_plugin_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MeterSphere - Remote Code Execution: MeterSphere is susceptible to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/metersphere/metersphere-plugin-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/plugin\/customMethod(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_office_webapps_ssrf {
    meta:
        attack_type = "vuln_office_webapps_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Office Web Apps Server Full Read - Server Side Request Forgery: Office Web Apps Server Full Read is vulnerable to SSRF."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/microsoft/office-webapps-ssrf.yaml"
    strings:
        $path0 = /\/oh\/wopi\/files\/@\/wFileId\/contents(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_mobileiron_log4j_rce {
    meta:
        attack_type = "vuln_mobileiron_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ivanti MobileIron (Log4j) - Remote Code Execution: Ivanti MobileIron is susceptible to remote code execution via the Apache Log4j2 library. Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/mobileiron/mobileiron-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mifs\/j_spring_security_check(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nagios_xi_xss {
    meta:
        attack_type = "vuln_nagios_xi_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Nagios XI 5.7.1 - Cross-Site Scripting: A reflected cross-site scripting (XSS) in Nagios XI 5.7.1 can result in an attacker performing malicious actions to users who open a maliciously crafted link or third-party web page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/nagios/nagios-xi-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/nagioslogserver\/login(\/|;|$)/ nocase
        $path1 = "/nagioslogserver/includes/components/ccm/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netgear_dgn_rce {
    meta:
        attack_type = "vuln_netgear_dgn_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Netgear DGN Devices - Command Execution: This template checks for unauthenticated command execution vulnerability in Netgear DGN devices. Attackers can bypass authentication mechanisms and execute arbitrary commands with root privileges."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/netgear/netgear-dgn-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])next_file=netgear\.cfg(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_netmizer_cmd_rce {
    meta:
        attack_type = "vuln_netmizer_cmd_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NetMizer LogManagement System cmd.php - Remote Code Execution: Remote Command Execution vulnerability in the NetMizer log management system cmd.php, and the attacker can execute the command by passing in the cmd parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/netmizer/netmizer-cmd-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/data\/manage\/cmd\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netsweeper_open_redirect {
    meta:
        attack_type = "vuln_netsweeper_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Netsweeper 4.0.9 - Open Redirect: Netsweeper 4.0.9 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/netsweeper/netsweeper-open-redirect.yaml"
    strings:
        $path0 = /\/webadmin\/authportal\/bounce\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netsweeper_rxss {
    meta:
        attack_type = "vuln_netsweeper_rxss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netsweeper 4.0.9 - Cross-Site Scripting: Netsweeper 4.0.9 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/netsweeper/netsweeper-rxss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])server=localhost(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_nodogsplash_lfi {
    meta:
        attack_type = "vuln_nodogsplash_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nodogsplash - Directory Traversal: Nodogsplash product was affected by a directory traversal vulnerability that also impacted the OpenWrt product. This vulnerability was addressed in Nodogsplash version 5.0.1. Exploiting this vulnerability, remote attackers could read arbitrary."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/nodogsplash-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/config\/nodogsplash(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nps_auth_bypass {
    meta:
        attack_type = "vuln_nps_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NPS - Authentication Bypass: This will reveal all parameters configured on the NPS, including the account username and password of the proxy."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/nps/nps-auth-bypass.yaml"
    strings:
        $path0 = /\/index\/gettunnel(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_odoo_xss {
    meta:
        attack_type = "vuln_odoo_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Odoo - Cross-Site Scripting: Odoo is a business suite that has features for many business-critical areas, such as e-commerce, billing, or CRM. Versions before the 16.0 release are vulnerable to CVE-2023-1434 and is caused by an incorrect content type being set on an API endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/odoo-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/web\/set_profiling(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_opencpu_rce {
    meta:
        attack_type = "vuln_opencpu_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenCPU - Remote Code Execution: Check for remote code execution via OpenCPU was conducted."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/opencpu/opencpu-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ocpu\/library\/base\/R\/do\.call\/json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_oracle_ebs_bispgrapgh_file_read {
    meta:
        attack_type = "vuln_oracle_ebs_bispgrapgh_file_read"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Oracle eBusiness Suite - Improper File Access: Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh. Be aware this product is no longer supported with patches or security fixes."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/oracle/oracle-ebs-bispgraph-file-access.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/OA_HTML\/jsp\/bsc\/bscpgraph\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_74cms_sqli {
    meta:
        attack_type = "vuln_74cms_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "74cms Sql Injection: A SQL injection vulnerability exists in 74cms 5.0.1 AjaxPersonalController.class.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/74cms-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])c=AjaxPersonal(&|$)/ nocase
        $param1 = /(^|[?&;])a=company_focus(&|$)/ nocase
        $param2 = /(^|[?&;])company_id\[0\]=match(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wso2_2019_0598 {
    meta:
        attack_type = "vuln_wso2_2019_0598"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 <5.8.0 - Server Side Request Forgery: WSO2 prior to version 5.8.0 is susceptible to a server-side request forgery vulnerability. This vulnerability can be exploited by misusing the UI gadgets loading capability of the shindig web application. An attacker can alter a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/WSO2-2019-0598.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/shindig\/gadgets\/proxy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aic_intelligent_password_exposure {
    meta:
        attack_type = "vuln_aic_intelligent_password_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AIC Intelligent Campus System - Password Exposure: Due to the design logic defects, the super password is leaked, which can kill more than 40 campus systems.<br>"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/aic-intelligent-password-exposure.yaml"
    strings:
        $path0 = /\/datacenter\/dataOrigin\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aishu_anyshare_info_exposure {
    meta:
        attack_type = "vuln_aishu_anyshare_info_exposure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Aishu AnyShare - Information Disclosure: Aishu AnyShare intelligent content management platform Usrm_GetAllUsers interface has an information disclosure vulnerability, and unauthenticated attackers can obtain sensitive information such as usernames and passwords. You can log in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/aishu-anyshare-info-exposure.yaml"
    strings:
        $path0 = /\/api\/ShareMgnt\/Usrm_GetAllUsers(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_alibaba_anyproxy_lfi {
    meta:
        attack_type = "vuln_alibaba_anyproxy_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Alibaba Anyproxy fetchBody File - Path Traversal: Alibaba Anyproxy is vulnerable to Path Traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/alibaba-anyproxy-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/fetchBody(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aspcms_commentlist_sqli {
    meta:
        attack_type = "vuln_aspcms_commentlist_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AspCMS commentList.asp - SQL Injection: An SQL injection vulnerability has been identified in the commentList.asp file of AspCMS. Exploiting this vulnerability, an attacker can illicitly acquire the administrator's MD5 password."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/aspcms-commentlist-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/plug\/comment\/commentList\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aspnuke_openredirect {
    meta:
        attack_type = "vuln_aspnuke_openredirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ASP-Nuke - Open Redirect: ASP-Nuke contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/aspnuke-openredirect.yaml"
    strings:
        $path0 = /\/gotoURL\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_avcon6_execl_lfi {
    meta:
        attack_type = "vuln_avcon6_execl_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AVCON6 org_execl_download.action - Arbitrary File Download: Arbitrary File Download vulnerability in the org_execl_download.action of the AVCON6 system management platform, through which an attacker can download arbitrary files from the server"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/avcon6-execl-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/org_execl_download\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_azon_dominator_sqli {
    meta:
        attack_type = "vuln_azon_dominator_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Azon Dominator - SQL Injection: Azon Dominator software is vulnerable to a sql attack at /fetch_products.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/azon-dominator-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])cid=1\*if\(now\(\)=sysdate\(\),sleep\(6\),0\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_bagisto_csti {
    meta:
        attack_type = "vuln_bagisto_csti"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bagisto 2.1.2 Client-Side Template Injection: Bagisto is vulnerable to Client-Side Template Injection (CSTI), which allows an attacker to execute arbitrary code on the server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/bagisto-csti.yaml"
        response_type = "template_eval"
    strings:
        $path0 = /\/bagisto-common\/search(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cacti_weathermap_file_write {
    meta:
        attack_type = "vuln_cacti_weathermap_file_write"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cacti Weathermap File Write: Cacti Weathermap (a plugin for Cacti, an open-source network monitoring and graphing tool) is vulnerable to file write."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/cacti-weathermap-file-write.yaml"
    strings:
        $path0 = /\/plugins\/weathermap\/editor\.php(\/|;|$)/ nocase
        $path1 = /\/plugins\/weathermap\/configs\/poc\.conf(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mapname=poc\.conf(&|$)/ nocase
        $param1 = /(^|[?&;])action=set_map_properties(&|$)/ nocase
        $param2 = /(^|[?&;])debug=existing(&|$)/ nocase
        $param3 = /(^|[?&;])node_iconfilename=--NONE--(&|$)/ nocase
        $param4 = /(^|[?&;])map_title=46ea1712d4b13b55b3f680cc5b8b54e8(&|$)/ nocase
        $param5 = /(^|[?&;])map_legend=Traffic Load(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_caimore_gateway_rce {
    meta:
        attack_type = "vuln_caimore_gateway_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CAIMORE Gateway - Remote Code Execution: The gateway of Xiamen Caimao Communication Technology Co., Ltd. is designed with open software architecture. It is a metal shell design, with two Ethernet RJ45 interfaces, and an industrial design wireless gateway using 3G/4G/5G wide."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/caimore-gateway-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goform\/formping(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_carrental_xss {
    meta:
        attack_type = "vuln_carrental_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Car Rental Management System 1.0 - Cross-Site Scripting: Car Rental Management System 1.0 contains a cross-site scripting vulnerability via admin/ajax.php?action=save_category in Name and Description parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/carrental-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=save_category(&|$)/ nocase
        $param1 = /(^|[?&;])page=categories(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_castel_digital_sqli {
    meta:
        attack_type = "vuln_castel_digital_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Castel Digital - Authentication Bypass: SQL Injection vulnerability in Castel Digital login forms."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/castel-digital-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/restrito/login/sub/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chamilo_lms_sqli {
    meta:
        attack_type = "vuln_chamilo_lms_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Chamilo 1.11.14 - SQL Injection: Chamilo 1.1.14 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/chamilo-lms-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/main\/inc\/ajax\/extra_field\.ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])a=search_options_from_tags(&|$)/ nocase
        $param1 = /(^|[?&;])field_id=image(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_chamilo_lms_xss {
    meta:
        attack_type = "vuln_chamilo_lms_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chamilo LMS 1.11.14 Cross-Site Scripting: Chamilo LMS 1.11.14 is vulnerable to cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/chamilo-lms-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/main\/calendar\/agenda_list\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_citrix_xenapp_log4j_rce {
    meta:
        attack_type = "vuln_citrix_xenapp_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix XenApp - Remote Code Execution (Apache Log4j): Citrix XenApp is susceptible to Log4j JNDI remote code execution. Citrix Virtual Apps is an application virtualization software produced by Citrix Systems that allows Windows applications to be accessed via individual."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/citrix-xenapp-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Citrix\/XenApp\/auth\/login\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cmseasy_crossall_sqli {
    meta:
        attack_type = "vuln_cmseasy_crossall_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CmsEasy crossall_act - SQL Injection: CmsEasy crossall_act.php SQL Injection Vulnerability. CmsEasy has a SQL injection vulnerability. Any SQL command can be executed by encrypting the SQL statement in the file service.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/cmseasy-crossall-act-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])case=crossall(&|$)/ nocase
        $param1 = /(^|[?&;])sql=WY8gzSfZwW9R5YvyK(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_coldfusion_debug_xss {
    meta:
        attack_type = "vuln_coldfusion_debug_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Adobe ColdFusion - Cross-Site Scripting: Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a remote host. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/coldfusion-debug-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/CFIDE\/debug\/cf_debugFr\.cfm(\/|;|$)/ nocase
        $path1 = /\/cfusion\/debug\/cf_debugFr\.cfm(\/|;|$)/ nocase
        $param0 = /(^|[?&;])userPage=javascript:alert\(1\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_comai_ras_cookie_bypass {
    meta:
        attack_type = "vuln_comai_ras_cookie_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Comai RAS System Cookie - Authentication Override: Comai RAS system has cookie authentication overreach, when RAS_Admin_UserInfo_UserName is set to admin, the background can be accessed"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/comai-ras-cookie-bypass.yaml"
    strings:
        $path0 = /\/Server\/CmxUser\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])pgid=UserList(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_commax_credentials_disclosure {
    meta:
        attack_type = "vuln_commax_credentials_disclosure"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "COMMAX Smart Home Ruvie CCTV Bridge DVR - RTSP Credentials Disclosure: The COMMAX CCTV Bridge for the DVR service allows an unauthenticated attacker to disclose real time streaming protocol (RTSP) credentials in plain-text."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/commax-credentials-disclosure.yaml"
    strings:
        $path0 = /\/overview\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_comtrend_password_exposure {
    meta:
        attack_type = "vuln_comtrend_password_exposure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Comtrend ADSL - Remote Code Execution: Comtrend ADSL CT-5367 C01_R12 router is susceptible to remote code execution. A remote user can execute arbitrary commands via the telnet interface, The password for this interface is leaked to unauthenticated users via the password.cgi."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/comtrend-password-exposure.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/password\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cpas_managment_lfi {
    meta:
        attack_type = "vuln_cpas_managment_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CPAS Management System - Arbitrary File Read: The CPAS Audit Management System has been found to contain a vulnerability that allows arbitrary file read. This security flaw can be exploited by attackers to access sensitive files on the server, potentially exposing critical."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/cpas-managment-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cpasm4\/plugInManController\/downPlugs(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fileId=\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_cpas_managment_sqli {
    meta:
        attack_type = "vuln_cpas_managment_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CPAS Management System - SQL Injection: The CPAS Audit Management System V4 has been identified with an SQL injection vulnerability in the getCurserIfAllowLogin endpoint. This flaw allows unauthenticated remote attackers to exploit the system by injecting malicious SQL queries.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/cpas-managment-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/cpasm4\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_cs_cart_unauthenticated_lfi {
    meta:
        attack_type = "vuln_cs_cart_unauthenticated_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CS-Cart - Local File Inclusion: CS-Cart is vulnerable to local file inclusion because it allows remote unauthenticated attackers to access locally stored files and reveal their content."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/cs-cart-unauthenticated-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/classes\/phpmailer\/class\.cs_phpmailer\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dicoogle_pacs_lfi {
    meta:
        attack_type = "vuln_dicoogle_pacs_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dicoogle PACS 2.5.0 - Local File Inclusion: Dicoogle PACS 2.5.0 is vulnerable to local file inclusion. This allows an attacker to read arbitrary files that the web user has access to. Admin credentials aren't required."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/dicoogle-pacs-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/exportFile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_discourse_xss {
    meta:
        attack_type = "vuln_discourse_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Discourse - Cross-Site Scripting: Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/discourse-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/email\/unsubscribed(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dlink_850l_info_leak {
    meta:
        attack_type = "vuln_dlink_850l_info_leak"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Dlink Dir-850L Info Leak"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/dlink-850L-info-leak.yaml"
    strings:
        $path0 = /\/hedwig\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_dss_download_fileread {
    meta:
        attack_type = "vuln_dss_download_fileread"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DSS Download - Local File Inclusion: DSS Download is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/dss-download-fileread.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/portal\/attachment_downloadByUrlAtt\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_duomicms_sql_injection {
    meta:
        attack_type = "vuln_duomicms_sql_injection"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Duomi CMS - SQL Injection: Duomi CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/duomicms-sql-injection.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/duomiphp\/ajax\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ecsimagingpacs_rce {
    meta:
        attack_type = "vuln_ecsimagingpacs_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ECSIMAGING PACS <= 6.21.5 - Command Execution and Local File Inclusion: ECSIMAGING PACS Application 6.21.5 and below suffer from a command injection vulnerability and a local file include vulnerability. The 'file' parameter on the page /showfile.php can be exploited to perform."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ecsimagingpacs-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/showfile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_eibiz_lfi {
    meta:
        attack_type = "vuln_eibiz_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion: Eibiz i-Media Server Digital Signage 3.8.0 is vulnerable to local file inclusion. An unauthenticated remote attacker can exploit this to view the contents of files located outside of the server's root directory.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/eibiz-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/dlibrary\/null(\/|;|$)/ nocase
        $param0 = /(^|[?&;])oldfile=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/windows\/win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ektron_blog_xmlrpc_xxe {
    meta:
        attack_type = "vuln_ektron_blog_xmlrpc_xxe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ektron CMS Blogs xmlrpc.aspx - XML External Entity Injection: Detects XML External Entity (XXE) vulnerability in Ektron CMS Blogs component (/WorkArea/Blogs/xmlrpc.aspx). Allows unauthenticated attackers to read local files or perform SSRF."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ektron-blog-xmlrpc-xxe.yaml"
    strings:
        $path0 = /\/WorkArea\/Blogs\/xmlrpc\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_elfinder_path_traversal {
    meta:
        attack_type = "vuln_elfinder_path_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "elFinder <=2.1.12 - Local File Inclusion: elFinder through 2.1.12 is vulnerable to local file inclusion via Connector.minimal.php in std42. This allows unauthenticated remote attackers to read, write, and browse files outside the configured document root. This is due to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/elFinder-path-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])target=l1_Li8vLi4vLy4uLy8uLi8vLi4vLy4uLy8uLi9ldGMvcGFzc3dk(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ems_sqli {
    meta:
        attack_type = "vuln_ems_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Employee Management System 1.0 - SQL Injection: Employee Management System 1.0 contains a SQL injection vulnerability via the username parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ems-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/process\/aprocess\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_enjoyrmis_sqli {
    meta:
        attack_type = "vuln_enjoyrmis_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "EnjoyRMIS - SQL Injection: EnjoyRMIS GetOAById has a SQL injection vulnerability, through which an attacker can obtain sensitive database information and even control the server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/enjoyrmis-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/EnjoyRMIS_WS\/WS\/POS\/cwsoa\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_epp_server_lfi {
    meta:
        attack_type = "vuln_epp_server_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "EPP Server - Local File Inclusion: servlet called 'CitiesServlet' that handles HTTP GET requests, so the user-provided input, obtained from the country parameter, is directly concatenated with the '/cities/cities_' string to form the fileName, This means an attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/epp-server-lfi.yaml"
    strings:
        $param0 = /(^|[?&;])country=\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_etouch_v2_sqli {
    meta:
        attack_type = "vuln_etouch_v2_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ECTouch 2 - SQL Injection: ECTouch 2 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/etouch-v2-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/upload\/mobile\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ewebs_arbitrary_file_reading {
    meta:
        attack_type = "vuln_ewebs_arbitrary_file_reading"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "EWEBS - Local File Inclusion: EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally stored files via the 'Language_S' parameter supplied to the 'casmain.xgi' endpoint."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ewebs-arbitrary-file-reading.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/casmain\.xgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])Language_S=\.\.\/\.\.\/Data\/CONFIG\/CasDbCnn\.dat(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_eyelock_nano_lfd {
    meta:
        attack_type = "vuln_eyelock_nano_lfd"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "EyeLock nano NXT 3.5 - Arbitrary File Retrieval: EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/eyelock-nano-lfd.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/scripts\/logdownload\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dlfilename=juicyinfo\.txt(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_f_secure_policymanager_log4j_rce {
    meta:
        attack_type = "vuln_f_secure_policymanager_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "F-Secure Policy Manager - Remote Code Execution (Apache Log4j): F-Secure Policy Manager is susceptible to Log4j JNDI remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/f-secure-policymanager-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/fsms\/fsmsh\.dll(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_fanruanoa2012_disclosure {
    meta:
        attack_type = "vuln_fanruanoa2012_disclosure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Fanruan Report 2012 Information Disclosure: Fanruan Report 2012 has an information disclosure vulnerability, and some sensitive information can be obtained by accessing a specific URL"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/fanruanoa2012-disclosure.yaml"
    strings:
        $path0 = /\/ReportServer(\/|;|$)/ nocase
        $param0 = /(^|[?&;])cmd=sc_getconnectioninfo(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_finecms_sqli {
    meta:
        attack_type = "vuln_finecms_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FineCMS 5.0.10 - SQL Injection: FineCMS 5.0.10 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/finecms-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])auth=582f27d140497a9d8f048ca085b111df(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_flexnet_log4j_rce {
    meta:
        attack_type = "vuln_flexnet_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flexnet - Remote Code Execution (Apache Log4j): Flexnet is susceptible to Log4j JNDI remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/flexnet-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/flexnet\/logon\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_fumasoft_sqli {
    meta:
        attack_type = "vuln_fumasoft_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fumasoft Cloud - SQL Injection: There is a SQL injection vulnerability in the AjaxMethod.ashx file of Fumasoft Cloud. Attackers can obtain server permissions through the vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/fumasoft-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/Ajax\/AjaxMethod\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=getEmpByname(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_global_domains_lfi {
    meta:
        attack_type = "vuln_global_domains_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Global Domains International - Local File Inclusion: Global Domains International is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/global-domains-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/kvmlm2\/index\.dhtml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_global_domains_xss {
    meta:
        attack_type = "vuln_global_domains_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Global Domains International - Cross-Site Scripting: Sites hosted by Global Domains International, Inc. have cross-site scripting and directory traversal vulnerabilities."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/global-domains-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/index\.dhtml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_glodon_linkworks_sqli {
    meta:
        attack_type = "vuln_glodon_linkworks_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Glodon Linkworks GWGdWebService - SQL injection: There is a SQL injection vulnerability in the GWGdWebService interface of Glodon Linkworks office OA. Sensitive information in the database can be obtained after sending a request package."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/glodon-linkworks-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/Org\/service\/Service\.asmx\/GetUserByEmployeeCode(\/|;|$)/ nocase
        $param0 = /(^|[?&;])employeeCode=1'-1\/user--'(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_gloo_unauth {
    meta:
        attack_type = "vuln_gloo_unauth"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Unauthenticated Gloo UI: Gloo UI is exposed to external users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/gloo-unauth.yaml"
    strings:
        $path0 = /\/fed\.rpc\.solo\.io\.GlooInstanceApi\/ListClusterDetails(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_goanywhere_mft_log4j_rce {
    meta:
        attack_type = "vuln_goanywhere_mft_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GoAnywhere Managed File Transfer - Remote Code Execution (Apache Log4j): GoAnywhere Managed File Transfer is vulnerable to a remote command execution (RCE) issue via the included Apache Log4j."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/goanywhere-mft-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goanywhere\/auth\/Login\.xhtml(\/|;|$)/ nocase
        $param0 = /(^|[?&;])formPanel:loginGrid:value_hinput=pass(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_goip_1_lfi {
    meta:
        attack_type = "vuln_goip_1_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GoIP-1 GSM - Local File Inclusion: GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET parameter in 'frame.html' or 'frame.A100.html' is not properly sanitized before being used to read files. This can be exploited by an."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/goip-1-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/default\/en_US\/frame\.html(\/|;|$)/ nocase
        $path1 = /\/default\/en_US\/frame\.A100\.html(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sidebar=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_gradio_file_redirect {
    meta:
        attack_type = "vuln_gradio_file_redirect"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Gradio - Open Redirect: An open redirect vulnerability in Gradio allows attackers to craft malicious URLs that redirect users to external, potentially harmful sites without proper validation."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/gradio-file-redirect.yaml"
    strings:
        $path0 = "/gradio_api/file=http:/example.com" ascii nocase
        $path1 = "/file=http:/example.com" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_groupoffice_lfi {
    meta:
        attack_type = "vuln_groupoffice_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Groupoffice 3.4.21 - Local File Inclusion: Groupoffice 3.4.21 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/groupoffice-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/compress\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_h3c_cnsss_arbitrary_file_upload {
    meta:
        attack_type = "vuln_h3c_cnsss_arbitrary_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "H3C CNSSS - Arbitrary File Upload: H3C-Campus Network Self-Service System vulnerability allows for arbitrary file uploads. This enables attackers to upload any files they choose, acquire webshells, manipulate server permissions, and access sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/h3c-cnsss-arbitrary-file-upload.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/imc\/primepush\/\.\.\/flexFileUpload(\/|;|$)/ nocase
        $path1 = "/imc/primepush/../flex/topobg/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_h3c_cvm_arbitrary_file_upload {
    meta:
        attack_type = "vuln_h3c_cvm_arbitrary_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "H3C CVM - Arbitrary File Upload: An H3C CVM vulnerability allows for arbitrary file uploads. This enables attackers to upload any files they choose, acquire webshells, manipulate server permissions, and access sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/h3c-cvm-arbitrary-file-upload.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cas\/fileUpload\/upload(\/|;|$)/ nocase
        $path1 = "/cas/js/lib/buttons/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_h3c_imc_rce {
    meta:
        attack_type = "vuln_h3c_imc_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "H3c IMC - Remote Code Execution: H3c IMC allows remote unauthenticated attackers to cause the remote web application to execute arbitrary commands via the 'dynamiccontent.properties.xhtml' endpoint."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/h3c-imc-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/imc\/javax\.faces\.resource\/dynamiccontent\.properties\.xhtml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hanming_lfr {
    meta:
        attack_type = "vuln_hanming_lfr"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hanming Video Conferencing - Local File Inclusion: Hanming Video Conferencing is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hanming-lfr.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/register\/toDownload\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hanta_rce {
    meta:
        attack_type = "vuln_hanta_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hanta Internet Behavior Management System - Remote Code Execution: Hanta Internet Behavior Management System is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hanta-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/dgn\/dgn_tools\/ping\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hashicorp_consul_rce {
    meta:
        attack_type = "vuln_hashicorp_consul_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hashicorp Consul Services API - Remote Code Execution: Hashicorp Consul Services API is vulnerable to an attack that can be leveraged to perform remote command execution on Consul nodes."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hashicorp-consul-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/v1\/agent\/service\/register(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hiboss_rce {
    meta:
        attack_type = "vuln_hiboss_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hiboss - Remote Code Execution: HiBoss allows remote unauthenticated attackers to cause the server to execute arbitrary code via the 'server_ping.php' endpoint and the 'ip' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hiboss-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/manager\/radius\/server_ping\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hongfan_ioffice_lfi {
    meta:
        attack_type = "vuln_hongfan_ioffice_lfi"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hongfan OA ioFileExport.aspx - Arbitrary File Read: Arbitrary File Read vulnerability in the Hongfan OA ioFileExport.aspx file, through which an attacker can obtain sensitive server information"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hongfan-ioffice-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ioffice\/prg\/set\/iocom\/ioFileExport\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])url=\/ioffice\/web\.config(&|$)/ nocase
        $param1 = /(^|[?&;])ContentType=application\/octet-stream(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_hongfan_ioffice_rce {
    meta:
        attack_type = "vuln_hongfan_ioffice_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongfan OA ioAssistance.asmx - Remote Code Execution: There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hongfan-ioffice-rce.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/ioffice\/prg\/set\/wss\/ioAssistance\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_hongfan_ioffice_sqli {
    meta:
        attack_type = "vuln_hongfan_ioffice_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongfan OA udfmr.asmx - SQL injection: There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/hongfan-ioffice-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/iOffice\/prg\/set\/wss\/udfmr\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_httpbin_contenttype_xss {
    meta:
        attack_type = "vuln_httpbin_contenttype_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HTTPBin - Cross-Site Scripting: HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/httpbin-contenttype-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])Content-Type=text\/html(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_huawei_router_auth_bypass {
    meta:
        attack_type = "vuln_huawei_router_auth_bypass"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Huawei Router - Authentication Bypass: Huawei Routers are vulnerable to authentication bypass because the default password of this router is the last 8 characters of the device's serial number which exist on the back of the device."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/huawei-router-auth-bypass.yaml"
    strings:
        $path0 = /\/api\/system\/deviceinfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_huiwen_bibliographic_info_leak {
    meta:
        attack_type = "vuln_huiwen_bibliographic_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Huiwen library bibliographic Retrieval System - Information Exposure: Huiwen library bibliographic retrieval system /include/config.properties file contains sensitive information, attackers can directly access to obtain information"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/huiwen-bibliographic-info-leak.yaml"
    strings:
        $path0 = /\/include\/config\.properties(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_interlib_fileread {
    meta:
        attack_type = "vuln_interlib_fileread"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Interlib - Local File Inclusion: Interlib has an arbitrary file read vulnerability. Attackers can use the vulnerability to read any file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/interlib-fileread.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/interlib\/report\/ShowImage(\/|;|$)/ nocase
        $param0 = /(^|[?&;])localPath=etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jeeplus_cms_resetpassword_sqli {
    meta:
        attack_type = "vuln_jeeplus_cms_resetpassword_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "JeePlus CMS - SQL Injection: A SQL injection vulnerability exists in the JeePlus low-code development platform, allowing attackers to manipulate database queries.This can lead to unauthorized data access, modification, or potential compromise of the application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/jeeplus-cms-resetpassword-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/a\/sys\/user\/resetPassword(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jeewms_lfi {
    meta:
        attack_type = "vuln_jeewms_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "JEEWMS - Local File Inclusion: JEEWMS is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/jeewms-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/systemController\/showOrDownByurl\.do(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dbPath=\.\.\/Windows\/win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jfrog_unauth_build_exposed {
    meta:
        attack_type = "vuln_jfrog_unauth_build_exposed"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JFrog Unauthentication Builds: JFrog Builds are exposed to Unauthenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/jfrog-unauth-build-exposed.yaml"
    strings:
        $path0 = /\/ui\/api\/v1\/global-search\/builds(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_jinfornet_jreport_lfi {
    meta:
        attack_type = "vuln_jinfornet_jreport_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jinfornet Jreport 15.6 - Local File Inclusion: Jinfornet Jreport 15.6 is vulnerable to local file incluion via the Jreport Help function in the SendFileServlet. Exploitaiton allows remote unauthenticated users to view any files on the Operating System with Application services."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/jinfornet-jreport-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/jreport\/sendfile\/help\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_joomla_jmarket_xss {
    meta:
        attack_type = "vuln_joomla_jmarket_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Joomla jMarket 5.15 - Cross-Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/joomla-jmarket-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])option=com_jvouchers(&|$)/ nocase
        $param1 = /(^|[?&;])controller=catalog-results(&|$)/ nocase
        $param2 = /(^|[?&;])trucs\[x\]\[search\]=gx3vt onfocus=alert\(document\.domain\) autofocus= itkrzsug7w5(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_justboil_me_image_upload {
    meta:
        attack_type = "vuln_justboil_me_image_upload"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JustBoil.me Images Plugin - Exposed Image Upload: JustBoil.me Images Plugin for TinyMCE contains an exposed dialog interface that could lead to potential security vulnerabilities. The plugin's dialog-v4.htm file is accessible without proper access controls, which may allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/justboil-me-image-upload.yaml"
    strings:
        $path0 = /\/plugins\/generic\/tinymce\/plugins\/justboil\.me\/dialog-v4\.htm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kavita_lfi {
    meta:
        attack_type = "vuln_kavita_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kavita - Local File Inclusion: Kavita - Path Traversal is vulnerable to local file inclusion via abusing the Path Traversal filename parameter of the /api/image/cover-upload."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/kavita-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])filename=\.\.\/appsettings\.json(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_khodrochi_cms_xss {
    meta:
        attack_type = "vuln_khodrochi_cms_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Khodrochi CMS - Cross Site Scripting: A cross site scripting vulnerability was found in the Khodrochi.ir CMS an Iranian Car Services Platform."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/khodrochi-cms-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/specification\/report\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kingdee_eas_directory_traversal {
    meta:
        attack_type = "vuln_kingdee_eas_directory_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kingdee EAS - Local File Inclusion: Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive server information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/kingdee-eas-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/appmonitor\/protected\/selector\/server_file\/files(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kingdee_erp_rce {
    meta:
        attack_type = "vuln_kingdee_erp_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kingdee OA Yunxingkong kdsvc - Remote Code Execution: Kingdee OA Yunxingkong has a remote command execution vulnerability. This vulnerability is caused by the fact that the communication layer of Kingdee Cloud Starry Sky Management Center adopts binary data format by default."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/kingdee-erp-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Kingdee\.BOS\.ServiceFacade\.ServicesStub\.DevReportService\.GetBusinessObjectData\.common\.kdsvc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kingsoft_v8_file_read {
    meta:
        attack_type = "vuln_kingsoft_v8_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kingsoft 8 - Local File Inclusion: Kingsoft 8 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/kingsoft-v8-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/htmltopdf\/downfile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_kingsoft_vgm_lfi {
    meta:
        attack_type = "vuln_kingsoft_vgm_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kingsoft VGM Antivirus - Arbitrary File Read: There is an arbitrary file reading vulnerability in Kingsoft Antivirus. An attacker can obtain any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/kingsoft-vgm-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/downFile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_landray_oa_datajson_rce {
    meta:
        attack_type = "vuln_landray_oa_datajson_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Landray OA Datajson S Bean - Remote Code Execution: Landray Office Automation (OA) software, specifically in the 's_bean' component's 'sysFormulaSimulateByJS' functionality. This vulnerability allows remote code execution (RCE), enabling attackers to execute arbitrary code on a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/landray-oa-datajson-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])s_bean=sysFormulaSimulateByJS(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_landray_oa_erp_data_rce {
    meta:
        attack_type = "vuln_landray_oa_erp_data_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Landray-OA - Remote Code Execution: Landray-OA `erp_data.jsp` is vulnerable to remote code execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/landray-oa-erp-data-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])erpServcieName=sysFormulaValidate(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_livebos_file_read {
    meta:
        attack_type = "vuln_livebos_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiveBOS ShowImage.do - Arbitrary File Read: An arbitrary file read vulnerability exists in the LiveBOS ShowImage.do interface, which can be exploited to obtain sensitive files from the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/livebos-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/feed\/ShowImage\.do;\.js\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])imgName=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_lucee_unset_credentials {
    meta:
        attack_type = "vuln_lucee_unset_credentials"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lucee - Unset Credentials: The Lucee admin panel has a first-time setup page which allows any user to set the administrator password."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/lucee-unset-credentials.yaml"
    strings:
        $path0 = /\/lucee\/admin\/web\.cfm(\/|;|$)/ nocase
        $path1 = /\/lucee\/admin\/server\.cfm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_luftguitar_arbitrary_file_upload {
    meta:
        attack_type = "vuln_luftguitar_arbitrary_file_upload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Luftguitar CMS Arbitrary File Upload: A vulnerability in Luftguitar CMS allows remote unauthenticated users to upload files to the remote service via the 'ftb.imagegallery.aspx' endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/luftguitar-arbitrary-file-upload.yaml"
    strings:
        $path0 = /\/ftb\.imagegallery\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_lvs_download_lfi {
    meta:
        attack_type = "vuln_lvs_download_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LVS DownLoad.aspx - Local File Inclusion (LFI): LVS lean value management system DownLoad.aspx has an arbitrary file reading vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/lvs-download-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/Business\/DownLoad\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])p=UploadFile\/\.\.\/Web\.Config(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_metinfo_lfi {
    meta:
        attack_type = "vuln_metinfo_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MetInfo <=6.1.0 - Local File Inclusion: MetInfo 6.0.0 through 6.1.0 is vulnerable to local file inclusion and allows remote unauthenticated attackers access to locally stored files and their content."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/metinfo-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/include\/thumb\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_microstrategy_ssrf {
    meta:
        attack_type = "vuln_microstrategy_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MicroStrategy tinyurl - Server-Side Request Forgery (Blind): Blind server-side (SSRF) request forgery vulnerability on MicroStrategy URL shortener."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/microstrategy-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/servlet\/taskProc(\/|;|$)/ nocase
        $path1 = /\/MicroStrategy\/servlet\/taskProc(\/|;|$)/ nocase
        $param0 = /(^|[?&;])taskId=shortURL(&|$)/ nocase
        $param1 = /(^|[?&;])srcURL=https:\/\/google\.com(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_motic_dsm_arbitrary_file_read {
    meta:
        attack_type = "vuln_motic_dsm_arbitrary_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MoticDSM - Arbitrary File Read: Motic Digital Slide Management System style has an arbitrary file reading vulnerability. Unauthenticated attackers can exploit this vulnerability to read important system files, leaving the website in a highly insecure state."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/motic-dsm-arbitrary-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/UploadService/Page/" ascii nocase
        $path1 = /\/UploadService\/Page\/style(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_mpsec_lfi {
    meta:
        attack_type = "vuln_mpsec_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MPSec ISG1000 - Local File Inclusion: MPSec ISG1000 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/mpsec-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/c:\/windows\/win\.ini(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_nacos_auth_bypass {
    meta:
        attack_type = "vuln_nacos_auth_bypass"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Nacos 1.x - Authentication Bypass: Nacos 1.x was discovered. A default Nacos instance needs to modify the application.properties configuration file or add the JVM startup variable Dnacos.core.auth.enabled=true to enable the authentication function (reference."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nacos-auth-bypass.yaml"
    strings:
        $path0 = /\/nacos\/v1\/auth\/users(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nacos_info_leak {
    meta:
        attack_type = "vuln_nacos_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nacos - Information Disclosure: Nacos unauthorized download of configuration information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nacos-info-leak.yaml"
    strings:
        $path0 = /\/v1\/cs\/configs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_natshell_rce {
    meta:
        attack_type = "vuln_natshell_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NatShell Debug File - Remote Code Execution: The NatShell debug file is susceptible to a remote code execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/natshell-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/debug\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ncast_lfi {
    meta:
        attack_type = "vuln_ncast_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ncast HD Intelligent Recording - Arbitrary File Reading: Ncast HD intelligent recording and broadcasting system has an arbitrary file reading vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ncast-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/developLog\/downloadLog\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netgear_router_exposure {
    meta:
        attack_type = "vuln_netgear_router_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NETGEAR Routers - Serial Number Disclosure: Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if password recovery is enabled."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/netgear-router-exposure.yaml"
    strings:
        $path0 = /\/rootDesc\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netgear_wac124_router_auth_bypass {
    meta:
        attack_type = "vuln_netgear_wac124_router_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NETGEAR WAC124 - Authentication Bypass: NETGEAR WAC124 AC2000 routers contain an authentication bypass vulnerability. An attacker can gain access by bypassing proper authentication, thereby making it possible to obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/netgear-wac124-router-auth-bypass.yaml"
    strings:
        $param0 = /(^|[?&;])next_file=debug\.htm(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_netis_info_leak {
    meta:
        attack_type = "vuln_netis_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netis E1+ V1.2.32533 - WiFi Password Disclosure: A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote device."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/netis-info-leak.yaml"
    strings:
        $path0 = /\/netcore_get\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_netpower_npfw_lfi {
    meta:
        attack_type = "vuln_netpower_npfw_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netpower NPFW - Local File Inclusion: Netpower NPFW firewall has an arbitrary file read vulnerability. Due to insufficient code filtering, it can read any file on the server"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/netpower-npfw-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/direct\/polling\/CommandsPolling\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nginx_webui_rce {
    meta:
        attack_type = "vuln_nginx_webui_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "nginxWebUI 3.5.0 - Remote Command Execution: There is a command execution vulnerability in the nginxWebUI backend. After logging in to the backend, the attacker can execute any command to obtain server permissions."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nginx-webui-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/adminPage\/remote\/cmdOver(\/|;|$)/ nocase
        $param0 = /(^|[?&;])remoteId=local(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_nginxwebui_runcmd_rce {
    meta:
        attack_type = "vuln_nginxwebui_runcmd_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "nginxWebUI 3.5.0 runCmd - Remote Command Execution: nginxWebUIs runCmd feature and is caused by incomplete validation of user input. Attackers can exploit the vulnerability by crafting malicious data to execute arbitrary commands on a vulnerable server without authorization."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nginxwebui-runcmd-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/AdminPage\/conf\/runCmd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nsasg_arbitrary_file_read {
    meta:
        attack_type = "vuln_nsasg_arbitrary_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NS ASG - Local File Inclusion: NS ASG is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ns-asg-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])file=pqpqpqpq\.txt(&|$)/ nocase
        $param1 = /(^|[?&;])certfile=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param2 = /(^|[?&;])certfile=cert_download\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_nsfocus_auth_bypass {
    meta:
        attack_type = "vuln_nsfocus_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nsfocus - Arbitrary User Login: Nsfocus bastion host has an arbitrary user login vulnerability. Attackers can use the vulnerability to log in any user by including www/local_user.php"
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nsfocus-auth-bypass.yaml"
    strings:
        $path0 = /\/api\/virtual\/home\/status(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nsfocus_lfi {
    meta:
        attack_type = "vuln_nsfocus_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nsfocus - Arbitrary File Read: Nsfocus bastion has an Arbitrary File Read Vulnerability through '/webconf/GetFile/'."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nsfocus-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/user\/requireLogin(\/|;|$)/ nocase
        $path1 = /\/webconf\/GetFile\/index(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_nuuo_file_inclusion {
    meta:
        attack_type = "vuln_nuuo_file_inclusion"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NUUO NVRmini 2 3.0.8 - Local File Inclusion: NUUO NVRmini 2 3.0.8 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nuuo-file-inclusion.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/css_parser\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_odoo_cms_redirect {
    meta:
        attack_type = "vuln_odoo_cms_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Odoo CMS - Open Redirect: Odoo CMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/odoo-cms-redirect.yaml"
    strings:
        $path0 = /\/website\/lang\/en_US(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_onlinefarm_management_xss {
    meta:
        attack_type = "vuln_onlinefarm_management_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Online Farm Management System 0.1.0 - Cross-Site Scripting: Online Farm Management System 0.1.0 contains a cross-site scripting vulnerability via the review.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/onlinefarm-management-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/reviewInput\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_opennms_log4j_rce {
    meta:
        attack_type = "vuln_opennms_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenNMS - JNDI Remote Code Execution (Apache Log4j): OpenNMS JNDI is susceptible to remote code execution via Apache Log4j 2.14.1 and before. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/opennms-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/opennms\/j_spring_security_check(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_opensis_lfi {
    meta:
        attack_type = "vuln_opensis_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "openSIS 5.1 - Local File Inclusion: openSIS 5.1 is vulnerable to local file inclusion and allows attackers to obtain potentially sensitive information by executing arbitrary local scripts in the context of the web server process. This may allow the attacker to compromise the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/opensis-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/opensis\/ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])modname=misc\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])bypass=Transcripts\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_opensns_rce {
    meta:
        attack_type = "vuln_opensns_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenSNS - Remote Code Execution: OpenSNS allows remote unauthenticated attackers to execute arbitrary code via the 'shareBox' endpoint."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/opensns-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])s=weibo\/Share\/shareBox(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_optilink_ont1gew_gpon_rce {
    meta:
        attack_type = "vuln_optilink_ont1gew_gpon_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OptiLink ONT1GEW GPON Remote Code Execution: OptiLink is susceptible to remote code execution vulnerabilities which could allow an authenticated, remote attacker to perform command injection attacks against an affected device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/optilink-ont1gew-gpon-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/boaform\/admin\/formTracert(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_oracle_fatwire_lfi {
    meta:
        attack_type = "vuln_oracle_fatwire_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Fatwire 6.3 - Path Traversal: Oracle Fatwire 6.3 suffers from a path traversal vulnerability in the getSurvey.jsp endpoint."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/oracle-fatwire-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cs\/career\/getSurvey\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_orbiteam_bscw_server_lfi {
    meta:
        attack_type = "vuln_orbiteam_bscw_server_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OrbiTeam BSCW Server - Local File Inclusion: OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/orbiteam-bscw-server-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])style_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_otobo_open_redirect {
    meta:
        attack_type = "vuln_otobo_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Otobo - Open Redirect: Otobo contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/otobo-open-redirect.yaml"
    strings:
        $path0 = /\/otobo\/index\.pl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_p7_office_xss {
    meta:
        attack_type = "vuln_p7_office_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "7-Office 12.5 - Cross-Site Scripting: A failure to implement proper measures to protect the structure of the web page in the P7-Office corporate server could have allowed a remote attacker to perform a cross-site scripting (XSS) attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/p7-office-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Products\/Files\/HttpHandlers\/filehandler\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_pacsone_server_lfi {
    meta:
        attack_type = "vuln_pacsone_server_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PACSOne Server 6.6.2 - Local File Inclusion: PACSOne Server 6.6.2 is vulnerable to local file inclusion via its integrated DICOM Web Viewer."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/pacsone-server-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/pacsone\/nocache\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_panmicro_arbitrary_file_read {
    meta:
        attack_type = "vuln_panmicro_arbitrary_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Panmicro E-Mobile System - Arbitrary File Read: The Panmicro E-Mobile client/cdnfile interface has an arbitrary file reading vulnerability. Unauthenticated attackers can use this vulnerability to read important system files, database configuration files, and so on."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/panmicro-arbitrary-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/client\/cdnfile\/1C\/Windows\/win\.ini(\/|;|$)/ nocase
        $path1 = /\/client\/cdnfile\/C\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_parentlink_xss {
    meta:
        attack_type = "vuln_parentlink_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Blackboard - Cross-Site Scripting: Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/parentlink-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/main\/blank(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_pbootcms_database_file_download {
    meta:
        attack_type = "vuln_pbootcms_database_file_download"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PbootCMS 2.0.7 - SQL Injection: PbootCMS 2.0.7 contains a SQL injection vulnerability via pbootcms.db. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/pbootcms-database-file-download.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/data\/pbootcms\.db(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_phpldapadmin_xss {
    meta:
        attack_type = "vuln_phpldapadmin_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHP LDAP Admin < 1.2.5 - Cross-Site Scripting: PHP LDAP Admin is vulnerable to XSS."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/phpldapadmin-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])cmd=template_engine(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_phpwiki_lfi {
    meta:
        attack_type = "vuln_phpwiki_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "phpwiki 1.5.4 - Cross-Site Scripting/Local File Inclusion: phpwiki 1.5.4 is vulnerable to cross-site scripting and local file inclusion, and allows remote unauthenticated attackers to include and return the content of locally stored files via the 'index.php' endpoint."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/phpwiki-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/phpwiki\/index\.php\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_pmb_directory_traversal {
    meta:
        attack_type = "vuln_pmb_directory_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PMB 5.6 - Local File Inclusion: PMB 5.6 is vulnerable to local file inclusion because the PMB Gif Image is not sanitizing the content of the 'chemin' parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/pmb-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/opac_css\/getgif\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])nomgif=tarik(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_pmb_xss {
    meta:
        attack_type = "vuln_pmb_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PMB v7.4.1 - Cross Site Scripting: PMB v7.4.1 allow attacker to inject arbitrary malicious HTML or Javascripts code in user web browser via no_search parameter"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/pmb-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])search_type_asked=extended_search(&|$)/ nocase
        $param1 = /(^|[?&;])op_0_f_1=EXACT(&|$)/ nocase
        $param2 = /(^|[?&;])field_0_f_1\[\]=gang(&|$)/ nocase
        $param3 = /(^|[?&;])search_xml_file=search_fields(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_podcast_generator_ssrf {
    meta:
        attack_type = "vuln_podcast_generator_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PodcastGenerator 3.2.9 - Blind SSRF via XML Injection: This is a SSRF vulnerability via Xml injection found in PodcastGenerator 3.2.9."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/podcast-generator-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/podcast\/PodcastGenerator\/admin\/login\.php(\/|;|$)/ nocase
        $path1 = /\/podcast\/PodcastGenerator\/admin\/episodes_upload\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_powercreator_cms_rce {
    meta:
        attack_type = "vuln_powercreator_cms_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PowerCreator CMS - Remote Code Execution: PowerCreator CMS is susceptible to a remote code execution vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/powercreator-cms-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/upload\/UploadResourcePic\.ashx(\/|;|$)/ nocase
        $path1 = "/ResourcePic/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_pyspider_unauthorized_access {
    meta:
        attack_type = "vuln_pyspider_unauthorized_access"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Pyspider Unauthorized Access: Unauthorized Access exists in PySpider which is an open-source web crawling and web scraping framework written in Python."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/pyspider-unauthorized-access.yaml"
    strings:
        $path0 = /\/debug\/pyspidervulntest\/run(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_qcubed_xss {
    meta:
        attack_type = "vuln_qcubed_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Qcubed - Cross-Site Scripting: Qcubed contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript via the /assets/php/_devtools/installer/step_2.php endpoint and the installation_path parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/qcubed-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/php\/_devtools\/installer\/step_2\.php(\/|;|$)/ nocase
        $path1 = /\/qcubed\/assets\/php\/_devtools\/installer\/step_2\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_qi_anxin_netkang_next_generation_firewall_rce {
    meta:
        attack_type = "vuln_qi_anxin_netkang_next_generation_firewall_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Qi'anxin Netkang Next Generation Firewall - Remote Code Execution: Qi'anxin Netkang Next Generation Firewall is susceptible to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/qi-anxin-netkang-next-generation-firewall-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/directdata\/direct\/router(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_qihang_media_lfi {
    meta:
        attack_type = "vuln_qihang_media_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "QiHang Media Web (QH.aspx) Digital Signage 3.0.9 - Arbitrary File Disclosure: The QiHang Media Web application suffers from an unauthenticated file disclosure vulnerability when input passed thru the filename parameter when using the download action or thru path parameter when."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/qihang-media-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])responderId=ResourceNewResponder(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_qizhi_fortressaircraft_unauth {
    meta:
        attack_type = "vuln_qizhi_fortressaircraft_unauth"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Qizhi Fortressaircraft Unauthorized Access: Qizhi Fortressaircraft is vulnerable to Unauthorized Access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/qizhi-fortressaircraft-unauth.yaml"
    strings:
        $path0 = /\/audit\/gui_detail_view\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_quick_cms_sqli {
    meta:
        attack_type = "vuln_quick_cms_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Quick.CMS v6.7 - SQL Injection: Quick.CMS version 6.7 suffers from a remote SQL injection vulnerability that allows for authentication bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/quick-cms-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])sEmail=test@test\.net(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_raisecom_rce {
    meta:
        attack_type = "vuln_raisecom_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Raisecom Gateway vpn_template_style.php - Remote Command Execution: The /vpn/vpn_template_style.php endpoint in Raisecom Multi-Service Intelligent Gateway is vulnerable to unauthenticated remote command execution. The stylenum parameter fails to properly sanitize user input."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/raisecom-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/vpn\/vpn_template_style\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_readymade_unilevel_xss {
    meta:
        attack_type = "vuln_readymade_unilevel_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Readymade Unilevel Ecommerce MLM - Cross-Site Scripting: Readymade Unilevel Ecommerce software has xss vulnerability in product-details.php?id"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/readymade-unilevel-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/product-details\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_reddittop_rss_xss {
    meta:
        attack_type = "vuln_reddittop_rss_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Reddit Top RSS - Cross-Site Scripting: Reddit Top RSS contains a cross-site scripting vulnerability via the /?subreddit=news&score= parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/reddittop-rss-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])subreddit=news(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_rentequip_xss {
    meta:
        attack_type = "vuln_rentequip_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "RentEquip Multipurpose Rental 1.0 - Cross Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/rentequip-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/shop\/products(\/|;|$)/ nocase
        $param0 = /(^|[?&;])category=cordless-tools(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_resin_inputfile_fileread {
    meta:
        attack_type = "vuln_resin_inputfile_fileread"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Caucho Resin LFR: A vulnerability in Caucho Resin allows remote unauthenticated users to utilize the 'inputFile' variable to include the content of locally stored files and disclose their content."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/resin-inputfile-fileread.yaml"
    strings:
        $path0 = /\/resin-doc\/resource\/tutorial\/jndi-appconfig\/test(\/|;|$)/ nocase
        $param0 = /(^|[?&;])inputFile=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/index\.jsp(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sangfor_cphp_rce {
    meta:
        attack_type = "vuln_sangfor_cphp_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sangfor Log Center - Remote Command Execution: Sangfor Log Center is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sangfor-cphp-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])strip_slashes=system(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sangfor_sysuser_conf {
    meta:
        attack_type = "vuln_sangfor_sysuser_conf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sangfor Application sys_user.conf Account Password Leakage: Sangfor application delivery management system file sys_user.conf can be directly accessed without authorization, resulting in leakage of account and password"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sangfor-sysuser-conf.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/tmp\/updateme\/sinfor\/ad\/sys\/sys_user\.conf(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seacms_sqli {
    meta:
        attack_type = "vuln_seacms_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SeaCMS 8.7 - SQL Injection: SeaCMS 8.7 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/seacms-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/comment\/api\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seeyon_oa_log4j_rce {
    meta:
        attack_type = "vuln_seeyon_oa_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Seeyon OA (Log4j) - Remote Code Execution: Seeyon OA is susceptible to remote code execution via the Apache Log4j 2 library prior to 2.15.0 by recording its own log information, specifically with specially crafted values sent as user input. Apache Log4j2 2.0-beta9 through."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/seeyon-oa-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])login\.timezone=GMT 8:00(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_seowon_router_rce {
    meta:
        attack_type = "vuln_seowon_router_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Seowon 130-SLC router - Remote Code Execution: Seowon 130-SLC router lets remote attackers execute commands without authentication as admin users via the router ip & Port(if available) in the request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/seowon-router-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])traceMode=trace(&|$)/ nocase
        $param1 = /(^|[?&;])queriesCnt=;cat \/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_servicenow_helpdesk_credential {
    meta:
        attack_type = "vuln_servicenow_helpdesk_credential"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ServiceNow Helpdesk Credential Exposure: Detection of exposed credentials in help the help desk JS file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/servicenow-helpdesk-credential.yaml"
    strings:
        $path0 = /\/HelpTheHelpDesk\.jsdbx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sharp_printers_lfi {
    meta:
        attack_type = "vuln_sharp_printers_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sharp Multifunction Printers - Local File Inclusion: It was observed that Sharp printers are vulnerable to a local file inclusion without authentication. Any attacker can read any file located in the printer."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sharp-printers-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/installed_emanual_down\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_siam_xss {
    meta:
        attack_type = "vuln_siam_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SIAM 2.0 - Cross-Site Scripting: A Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the SIAM Invitation application. The url parameter of the qrcode.jsp page does not properly sanitize user input, allowing the injection and execution of malicious."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/siam-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/siam-convite\/qrcode\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sick_beard_xss {
    meta:
        attack_type = "vuln_sick_beard_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sickbeard - Cross-Site Scripting: Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sick-beard-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/config\/postProcessing\/testNaming(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_siteminder_dom_xss {
    meta:
        attack_type = "vuln_siteminder_dom_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SiteMinder - DOM Cross-Site Scripting: SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/siteminder-dom-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/siteminderagent\/forms\/smpwservices\.fcc(\/|;|$)/ nocase
        $path1 = /\/siteminderagent\/forms\/smaceauth\.fcc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_slims_8_akasia_xss {
    meta:
        attack_type = "vuln_slims_8_akasia_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Senayan Library Management System v8.3.1 (Akasia) - Cross-Site Scripting: SLiMS 8.3.1 (Akasia) has a `destination` parameter that is vulnerable to reflected XSS. However, ensure that the `p` parameter points to the 'member'. Additional google dork 'intext:'SLiMS 8.3.1 (Akasia)''."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/slims-8-akasia-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/perpustakaan\/index\.php(\/|;|$)/ nocase
        $path1 = /\/slims\/index\.php(\/|;|$)/ nocase
        $path2 = /\/perpustakaan\/slims\/index\.php(\/|;|$)/ nocase
        $path3 = /\/e-library\/index\.php(\/|;|$)/ nocase
        $path4 = /\/perpus\/index\.php(\/|;|$)/ nocase
        $path5 = /\/digilib\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_slims_xss {
    meta:
        attack_type = "vuln_slims_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Senayan Library Management System v9.4.0(SLIMS 9) - Cross Site Scripting: SLIMS 9 was discovered to contain `destination` request parameter that copies the value of an HTML tag attribute which is encapsulated in double quotation marks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/slims-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])memberPassWord=password(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sofneta_mecdream_pacs_lfi {
    meta:
        attack_type = "vuln_sofneta_mecdream_pacs_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Softneta MedDream PACS Server Premium 6.7.1.1 - Local File Inclusion: Softneta MedDream PACS Server Premium 6.7.1.1 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sofneta-mecdream-pacs-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/pacs\/nocache\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_solarview_compact_xss {
    meta:
        attack_type = "vuln_solarview_compact_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SolarView Compact 6.00 - Cross-Site Scripting: SolarView Compact 6.00 contains a cross-site scripting vulnerability via fname at /Solar_Image.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/solarview-compact-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Solar_Image\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sonicwall_nsm_log4j_rce {
    meta:
        attack_type = "vuln_sonicwall_nsm_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sonicwall NSM - Remote Code Execution (Apache Log4j): Sonicwall NSM is susceptible to Log4j JNDI remote code execution. SonicWall Network Security Manager (NSM) allows you to centrally orchestrate all firewall operations error-free, see and manage threats and risks across your."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sonicwall-nsm-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/sonicos\/auth(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sonicwall_sslvpn_shellshock {
    meta:
        attack_type = "vuln_sonicwall_sslvpn_shellshock"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sonicwall SSLVPN - Remote Code Execution (ShellShock): Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execute arbitrary commands."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sonicwall-sslvpn-shellshock.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/jarrewrite\.sh(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sound4_file_disclosure {
    meta:
        attack_type = "vuln_sound4_file_disclosure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SOUND4 IMPACT/FIRST/PULSE/Eco <=2.x (PHPTail) Unauthenticated File Disclosure: The application suffers from an unauthenticated file disclosure vulnerability. Using the 'file' GET parameter attackers can disclose arbitrary files on the affected device and disclose sensitive and."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sound4-file-disclosure.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cgi-bin\/loghandler\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sslvpn_client_rce {
    meta:
        attack_type = "vuln_sslvpn_client_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SSL VPN Client - Remote Code Execution: SSL VPN Client is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/sslvpn-client-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/sslvpn\/sslvpn_client\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])client=logoImg(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_symantec_messaging_gateway {
    meta:
        attack_type = "vuln_symantec_messaging_gateway"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Symantec Messaging Gateway <=10.6.1 - Local File Inclusion: Symantec Messaging Gateway 10.6.1 and prior are vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/symantec-messaging-gateway.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/brightmail\/servlet\/com\.ve\.kavachart\.servlet\.ChartStream(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tamronos_user_creation {
    meta:
        attack_type = "vuln_tamronos_user_creation"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TamronOS IPTV - Arbitrary User Creation: Unathenticated attackers can create multiple users in TamronOS IPTV."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/tamronos-user-creation.yaml"
    strings:
        $path0 = /\/api\/manager\/submit(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tianqing_info_leak {
    meta:
        attack_type = "vuln_tianqing_info_leak"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tianqing Info Leak: Information exposed in Tianqing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/tianqing-info-leak.yaml"
    strings:
        $path0 = /\/api\/dbstat\/gettablessize(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tikiwiki_reflected_xss {
    meta:
        attack_type = "vuln_tikiwiki_reflected_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tiki Wiki CMS Groupware 5.2 - Cross-Site Scripting: Tiki Wiki CMS Groupware 5.2 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/tikiwiki-reflected-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/tiki-5\.2\/tiki-edit_wiki_section\.php(\/|;|$)/ nocase
        $path1 = /\/tiki-edit_wiki_section\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tikiwiki_xss {
    meta:
        attack_type = "vuln_tikiwiki_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tiki Wiki CMS Groupware v25.0 - Cross Site Scripting: Tiki Wiki CMS Groupware version 25.0 suffers from a cross site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/tikiwiki-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])controller=comment(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tpshop_directory_traversal {
    meta:
        attack_type = "vuln_tpshop_directory_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TPshop - Local File Inclusion: TPshop is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/tpshop-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/index\.php\/Home\/uploadify\/fileList(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_turbocrm_xss {
    meta:
        attack_type = "vuln_turbocrm_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TurboCRM - Cross-Site Scripting: TurboCRM contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript into the response returned by the application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/turbocrm-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/login\/forgetpswd\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ueditor_file_upload {
    meta:
        attack_type = "vuln_ueditor_file_upload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "UEditor - Arbitrary File Upload: UEditor contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/ueditor-file-upload.yaml"
    strings:
        $path0 = /\/ueditor\/net\/controller\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])encode=utf-8(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_umbraco_base_ssrf {
    meta:
        attack_type = "vuln_umbraco_base_ssrf"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Umbraco 8.14.1 - baseUrl Server-Side Request Forgery (SSRF): Umbraco 8.1.4.1 allows attackers to use the baseUrl parameter to several programs to perform a server-side request forgery (SSRF) attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/umbraco-base-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/umbraco\/BackOffice\/Api\/Help\/GetContextHelpForPage(\/|;|$)/ nocase
        $path1 = /\/umbraco\/backoffice\/UmbracoApi\/Dashboard\/GetRemoteDashboardContent(\/|;|$)/ nocase
        $path2 = /\/umbraco\/backoffice\/UmbracoApi\/Dashboard\/GetRemoteDashboardCss(\/|;|$)/ nocase
        $param0 = /(^|[?&;])section=content(&|$)/ nocase
        $param1 = /(^|[?&;])tree=undefined(&|$)/ nocase
        $param2 = /(^|[?&;])section=TryToAvoidGetCacheItem111(&|$)/ nocase
        $param3 = /(^|[?&;])section=AvoidGetCacheItem(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_unauth_spark_api {
    meta:
        attack_type = "vuln_unauth_spark_api"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Unauthenticated Spark REST API: The Spark product's REST API interface allows access to unauthenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/unauth-spark-api.yaml"
    strings:
        $path0 = /\/v1\/submissions(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vlife_fastjson_rce {
    meta:
        attack_type = "vuln_vlife_fastjson_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Vlife FastJSON - Remote Code Execution: alibaba/fastjson v1.2.67 within the MyUsernamePasswordAuthenticationFilter for processing authentication requests. The /vlife/login endpoint directly deserializes the raw HTTP request body using JSON.parseObject() without enforcing type."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/vlife-fastjson-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/vlife\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vmware_siterecovery_log4j_rce {
    meta:
        attack_type = "vuln_vmware_siterecovery_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware Site Recovery Manager - Remote Code Execution (Apache Log4j): VMware Site Recovery Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/vmware-siterecovery-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/dr\/authentication\/oauth2\/oauth2login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_voyager_lfi {
    meta:
        attack_type = "vuln_voyager_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Voyager 1.3.0 - Directory Traversal: Voyager 1.3.0 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/voyager-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/admin\/voyager-assets(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wapples_firewall_lfi {
    meta:
        attack_type = "vuln_wapples_firewall_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wapples Web Application Firewall - Local File Inclusion: Wapples Web Application Firewall is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/wapples-firewall-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/webapi\/file\/transfer(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_webpagetest_ssrf {
    meta:
        attack_type = "vuln_webpagetest_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Web Page Test - Server Side Request Forgery (SSRF): Web Page Test is vulnerable to SSRF."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/webpagetest-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/jpeginfo\/jpeginfo\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_webui_rce {
    meta:
        attack_type = "vuln_webui_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WebUI 1.5b6 - Remote Code Execution: WebUI 1.5b6 is vulnerable to remote code execution because the 'mainfile.php' endpoint allows remote attackersto execute arbitrary code via the 'Logon' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/webui-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mainfile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wems_manager_xss {
    meta:
        attack_type = "vuln_wems_manager_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WEMS Enterprise Manager - Cross-Site Scripting: WEMS Enterprise Manager contains a cross-site scripting vulnerability via the /guest/users/forgotten endpoint and the email parameter, which allows a remote attacker to inject arbitrary JavaScript into the response return by the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/wems-manager-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/guest\/users\/forgotten(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wifisky7_rce {
    meta:
        attack_type = "vuln_wifisky7_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WIFISKY-7 Layer Flow Control Router - Remote Code Execution: There is an RCE vulnerability in the confirm.php interface of WIFISKY-7 layer flow control router"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/wifisky7-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/notice\/confirm\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_publishpress_capabilities_xss {
    meta:
        attack_type = "vuln_wp_publishpress_capabilities_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PublishPress Capabilities < 2.3.3 - Cross-Site Scripting: The PublishPress Capabilities plugin for WordPress before 2.3.3 does not escape a form action URL before outputting it back in an attribute, leading to Reflected Cross-Site Scripting (XSS)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/wp-publishpress-capabilities-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=pp-capabilities-roles(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wyse_devicegroup_register {
    meta:
        attack_type = "vuln_wyse_devicegroup_register"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dell Wyse Management Suite - Unauthenticated Device Registration: Dell Wyse Management Suite allows unauthenticated device registration by chaining deviceGroupLogin2 and deviceRegister endpoints, leaking wyseIdentifier and authenticationCode."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/wyse-devicegroup-register.yaml"
    strings:
        $path0 = /\/ccm-web\/open\/deviceGroupLogin2(\/|;|$)/ nocase
        $path1 = /\/ccm-web\/open\/deviceRegister(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_xerox_efi_lfi {
    meta:
        attack_type = "vuln_xerox_efi_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion: Xerox DC260 EFI Fiery Controller Webtools 2.0 is vulnerable to local file inclusion because input passed thru the 'file' GET parameter in 'forceSave.php' script is not properly sanitized before being used to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/xerox-efi-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wt3\/forceSave\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yapi_rce {
    meta:
        attack_type = "vuln_yapi_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yapi - Remote Code Execution: Yapi allows remote unauthenticated attackers to cause the product to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yapi-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/group\/list(\/|;|$)/ nocase
        $path1 = /\/api\/project\/add(\/|;|$)/ nocase
        $path2 = /\/api\/project\/get(\/|;|$)/ nocase
        $path3 = /\/api\/interface\/add(\/|;|$)/ nocase
        $path4 = /\/api\/plugin\/advmock\/save(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yarn_resourcemanager_rce {
    meta:
        attack_type = "vuln_yarn_resourcemanager_rce"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Apache Hadoop YARN ResourceManager - Remote Code Execution: Apache Hadoop YARN ResourceManager is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yarn-resourcemanager-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ws\/v1\/cluster\/apps\/new-application(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yeswiki_stored_xss {
    meta:
        attack_type = "vuln_yeswiki_stored_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "YesWiki - Stored Cross-Site Scripting: YesWiki contains a stored contains a cross-site scripting vulnerability via the bf_text field when adding a new entry for Forum."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yeswiki-stored-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])vue=consulter(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_yibao_sqli {
    meta:
        attack_type = "vuln_yibao_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Yibao OA System - SQL Injection: Yibao OA System is vulnerable to SQL Injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yibao-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/system\/ExecuteSqlForSingle(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yishaadmin_lfi {
    meta:
        attack_type = "vuln_yishaadmin_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "yishaadmin - Local File Inclusion: yishaadmin is vulnerable to local file inclusion via the '/admin/File/DownloadFile' endpoint and allows files to be downloaded, read or deleted without any authentication."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yishaadmin-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/admin\/File\/DownloadFile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yunanbao_rce {
    meta:
        attack_type = "vuln_yunanbao_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yunanbao Cloud Box FastJson - Deserialization Remote Code Execution: The authService interface of Cloud Box uses the vulnerable fastjson component. Unauthorized attackers can launch attacks on Cloud Box through the fastjson serialization vulnerability to obtain server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/yunanbao-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/3\.0\/authService\/config(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zcms_v3_sqli {
    meta:
        attack_type = "vuln_zcms_v3_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZCMS - SQL Injection: ZCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/zcms-v3-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/admin\/cms_channel\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zhixiang_oa_msglog_sqli {
    meta:
        attack_type = "vuln_zhixiang_oa_msglog_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Zhixiang OA msglog.aspx - SQL injection: There is a SQL injection vulnerability in the msglog.aspx file of Zhixiang OA. Attackers can obtain sensitive information through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/zhixiang-oa-msglog-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/mainpage\/msglog\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zimbra_preauth_ssrf {
    meta:
        attack_type = "vuln_zimbra_preauth_ssrf"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zimbra Collaboration Suite - Server-Side Request Forgery: Zimbra Collaboration Suite (ZCS) allows remote unauthenticated attackers to cause the product to include content returned by third-party servers and use it as its own code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/zimbra-preauth-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/service\/error\/sfdc_preauth\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zqnb_educationcloud_exposure {
    meta:
        attack_type = "vuln_zqnb_educationcloud_exposure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ZhongQing Education Cloud Platform - Information Exposure: Zhongqing Naboo Education Cloud Platform is a deep application supporting teaching and research. Information leakage and unauthorized access exist in the cloud platform system. The password can be reset to 123456."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/zqnb-educationcloud-exposure.yaml"
    strings:
        $path0 = /\/api\/TeacherQuery\/SearchTeacherInSiteWithPagerRecords(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zzcms_xss {
    meta:
        attack_type = "vuln_zzcms_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ZZCMS - Cross-Site Scripting: ZZCMS contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/zzcms-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/logincheck\.php(\/|;|$)/ nocase
        $path1 = /\/admin\/usermodify\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_phoenix_contact_charx_multiple_vulnerabilities {
    meta:
        attack_type = "vuln_phoenix_contact_charx_multiple_vulnerabilitie"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Phoenix Contact CHARX SEC-3XXX AC Controller < 1.7.3 - Multiple Vulnerabilities: Multiple vulnerabilities exist in Phoenix Contact CHARX SEC-3XXX AC Controller versions prior to 1.7.3. Successful exploitation may allow attackers to bypass authentication, disclose sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/phoenix-contact/phoenix-contact-charx-multiple-vulnerabilities.yaml"
    strings:
        $path0 = /\/api\/v1\.0\/web\/retained-data(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_phpjabbers_event_booking_xss {
    meta:
        attack_type = "vuln_phpjabbers_event_booking_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPJabbers Event Booking Calendar - Reflected XSS: Detected that PHPJabbers Event Booking Calendar contained a reflected cross-site scripting vulnerability in the preview.php endpoint"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/phpjabbers/phpjabbers-event-booking-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/scripts\/event-booking-calendar\/preview\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_pkp_lib_open_redirect {
    meta:
        attack_type = "vuln_pkp_lib_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Open Journal Systems pkp-lib - Open Redirect: Public Knowledge Project pkp-lib is vulnerable to Open redirect due to a lack of input sanitization in the setLocale function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/pkp-lib-open-redirect.yaml"
    strings:
        $path0 = /\/index\.php\/index\/user\/setLocale\/NEW_LOCALE(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_portainer_init_deploy {
    meta:
        attack_type = "vuln_portainer_init_deploy"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Portainer - Init Deploy Discovery: Portainer initialization deployment files were discovered."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/portainer-init-deploy.yaml"
    strings:
        $path0 = /\/api\/users\/admin\/check(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_prestashop_blocktestimonial_file_upload {
    meta:
        attack_type = "vuln_prestashop_blocktestimonial_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Prestashop Blocktestimonial Modules - File Upload Vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/prestashop/prestashop-blocktestimonial-file-upload.yaml"
    strings:
        $path0 = /\/modules\/blocktestimonial\/addtestimonial\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_secsslvpn_auth_bypass {
    meta:
        attack_type = "vuln_secsslvpn_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Secure Access Gateway SecSSLVPN - Authentication Bypass: The Secure Access Gateway SecSSL 3600 secure access gateway system has an unauthorized access vulnerability. An attacker can obtain the user list and modify the user account password through the vulnerability."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/qax/secsslvpn-auth-bypass.yaml"
    strings:
        $path0 = /\/admin\/group\/x_group\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_qibocms_file_download {
    meta:
        attack_type = "vuln_qibocms_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Qibocms - Arbitrary File Download: Qibocms is vulnerable to arbitrary file download vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/qibocms-file-download.yaml"
    strings:
        $param0 = /(^|[?&;])url=ZGF0YS9jb25maWcucGg8(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_rails6_xss {
    meta:
        attack_type = "vuln_rails6_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ruby on Rails - CRLF Injection and Cross-Site Scripting: Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/rails/rails6-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/rails\/actions(\/|;|$)/ nocase
        $param0 = /(^|[?&;])error=ActiveRecord::PendingMigrationError(&|$)/ nocase
        $param1 = /(^|[?&;])action=Run pending migrations(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_realor_gwt_system_sqli {
    meta:
        attack_type = "vuln_realor_gwt_system_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Realor GWT System SQL injection: Realor GWT System system improperly handles the security of data passed by users, resulting in a SQL injection vulnerability. Remote and unauthorized attackers can use this vulnerability to obtain sensitive information in the database, and can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/realor/realor-gwt-system-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/AgentBoard\.XGI(\/|;|$)/ nocase
        $path1 = /\/Board\.XGI(\/|;|$)/ nocase
        $param0 = /(^|[?&;])cmd=UserLogin(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_retool_postmessage_xss {
    meta:
        attack_type = "vuln_retool_postmessage_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Retool Self-Hosted - postMessage XSS via Custom Component Collections: Retool Self-Hosted versions 3.284.0 through 3.284.11 contain a cross-site scripting (XSS) vulnerability in the custom component collections iframe handler. The postMessage event listener in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/retool/retool-postmessage-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/custom-component-collections\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_retool_svg_xss {
    meta:
        attack_type = "vuln_retool_svg_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Retool < 3.88 - SVG Cross-Site Scripting: This template checks for SVG Cross-Site Scripting(XSS) vulnerability via the Image Proxy URL parameter in Retool."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/retool/retool-svg-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/imageProxy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_rocketchat_unauth_access {
    meta:
        attack_type = "vuln_rocketchat_unauth_access"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "RocketChat Live Chat - Unauthenticated Read Access: RocketChat Live Chat accepts invalid parameters that could potentially allow unauthenticated access to messages and user tokens."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/rocketchat/unauth-message-read.yaml"
    strings:
        $path0 = /\/api\/v1\/method\.callAnon\/cve_exploit(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_royalevent_stored_xss {
    meta:
        attack_type = "vuln_royalevent_stored_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Royal Event Management System - Stored Cross-Site Scripting: Royal Event Management System contains a stored cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/royalevent/royalevent-stored-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/royal_event\/companyprofile\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])country=India(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ruijie_excu_shell {
    meta:
        attack_type = "vuln_ruijie_excu_shell"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ruijie Switch Web Management System EXCU_SHELL - Information Disclosure: Ruijie switch WEB management system is vulnerable to an EXCU_SHELL information disclosure issue, potentially exposing sensitive system information to unauthorized parties."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/ruijie/ruijie-excu-shell.yaml"
    strings:
        $path0 = /\/EXCU_SHELL(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ruijie_nbr_fileupload {
    meta:
        attack_type = "vuln_ruijie_nbr_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ruijie NBR fileupload.php - Arbitrary File Upload: Ruijie NBR router fileupload.php file has an arbitrary file upload vulnerability. An attacker can upload any file to the server through the vulnerability to obtain server permissions."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/ruijie/ruijie-nbr-fileupload.yaml"
    strings:
        $path0 = /\/ddi\/server\/fileupload\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])uploadDir=upload(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ruijie_nmc_sync_rce {
    meta:
        attack_type = "vuln_ruijie_nmc_sync_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ruijie RG-UAC nmc_sync.php - Remote Code Execution: There is a command execution vulnerability in the nmc_sync.php interface of Ruijie's RG-UAC unified online behavior management and audit system. An unauthenticated attacker can execute arbitrary commands to control server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/ruijie/ruijie-nmc-sync-rce.yaml"
    strings:
        $path0 = /\/view\/systemConfig\/management\/nmc_sync\.php(\/|;|$)/ nocase
        $path1 = "/view/systemConfig/management/" ascii nocase
        $param0 = /(^|[?&;])center_ip=127\.0\.0\.1(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sangfor_edr_rce {
    meta:
        attack_type = "vuln_sangfor_edr_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sangfor EDR 3.2.17R1/3.2.21 - Remote Code Execution: Sangfor EDR 3.2.17R1/3.2.21 allows remote unauthenticated users to to execute arbitrary commands."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/sangfor/sangfor-edr-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/edr\/sangforinter\/v2\/cssp\/slog_client(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sangfor_login_rce {
    meta:
        attack_type = "vuln_sangfor_login_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sangfor Application Login - Remote Command Execution: Sangfor application delivery management system login has a remote command execution vulnerability, through which an attacker can obtain server privileges and execute arbitrary commands"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/sangfor/sangfor-login-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])log_type=report(&|$)/ nocase
        $param1 = /(^|[?&;])loginType=account(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_sangfor_nextgen_lfi {
    meta:
        attack_type = "vuln_sangfor_nextgen_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sangfor Next Gen Application Firewall - Arbitary File Read: Sangfor Next Gen Application Firewall is susceptible to Local File Inclusion as it does not validate the file parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/sangfor/sangfor-ngaf-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/svpn_html\/loadfile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seeyon_config_exposure {
    meta:
        attack_type = "vuln_seeyon_config_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Seeyon OA A6 config.jsp - Information Disclosure: The Seeyon OA A6 config.jsp page can be accessed without authorization, resulting in sensitive information leakage vulnerabilities, through which attackers can obtain sensitive information in the server"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/seeyon-config-exposure.yaml"
    strings:
        $path0 = /\/yyoa\/ext\/trafaxserver\/SystemManage\/config\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seeyon_createmysql_exposure {
    meta:
        attack_type = "vuln_seeyon_createmysql_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Seeyon OA A6 createMysql.jsp Database - Information Disclosure: Seeyon OA A6 has leaked sensitive database information. An attacker can obtain the database account and password MD5 by accessing a specific URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/seeyon-createmysql-exposure.yaml"
    strings:
        $path0 = /\/yyoa\/createMysql\.jsp(\/|;|$)/ nocase
        $path1 = /\/yyoa\/ext\/createMysql\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seeyon_initdata_exposure {
    meta:
        attack_type = "vuln_seeyon_initdata_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Seeyon OA A6 initDataAssess.jsp - Information Disclosure: Seeyon OA A6 initDataAssess.jsp has leaked user sensitive information, attacker can use the obtained username to blast the user's password to enter the background for further attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/seeyon-initdata-exposure.yaml"
    strings:
        $path0 = /\/yyoa\/assess\/js\/initDataAssess\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seeyon_oa_fastjson_rce {
    meta:
        attack_type = "vuln_seeyon_oa_fastjson_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Seeyon OA Fastjson Remote Code Execution: Seeyon OA Fastjson is vulnerable to RCE."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/seeyon-oa-fastjson-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])method=changeLocale(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_seeyon_oa_setextno_sqli {
    meta:
        attack_type = "vuln_seeyon_oa_setextno_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Seeyon OA A6 setextno.jsp - SQL Injection: Seeyon OA A6 initDataAssess.jsp has leaked user sensitive information,You can blast the user password through the obtained username to enter the background for further attacks"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/seeyon-oa-setextno-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/yyoa\/ext\/trafaxserver\/ExtnoManage\/setextno\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zhiyuan_file_upload {
    meta:
        attack_type = "vuln_zhiyuan_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zhiyuan OA Arbitrary File Upload Vulnerability: A vulnerability in Zhiyuan OA allows remote unauthenticated attackers to upload arbitrary files to the remote server and cause execute arbitrary code to be executed."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/zhiyuan-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/seeyon\/thirdpartyController\.do\.css\/\.\.;\/ajax\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zhiyuan_oa_info_leak {
    meta:
        attack_type = "vuln_zhiyuan_oa_info_leak"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Zhiyuan Oa A6-s info Leak"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/zhiyuan-oa-info-leak.yaml"
    strings:
        $path0 = /\/yyoa\/DownExcelBeanServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])contenttype=username(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_zhiyuan_oa_session_leak {
    meta:
        attack_type = "vuln_zhiyuan_oa_session_leak"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zhiyuan OA Session Leak: A vulnerability in Zhiyuan OA allows remote unauthenticated users access to sensitive session information via the 'getSessionList.jsp' endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/seeyon/zhiyuan-oa-session-leak.yaml"
    strings:
        $path0 = /\/yyoa\/ext\/https\/getSessionList\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_smartbi_deserialization {
    meta:
        attack_type = "vuln_smartbi_deserialization"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Smartbi windowunloading Interface - Deserialization: The Smartbi big data analysis platform has a remote command execution vulnerability. An unauthenticated remote attacker can use the stub interface to construct a request to bypass patch restrictions and then control the JDBC."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/smartbi/smartbi-deserialization.yaml"
    strings:
        $param0 = /(^|[?&;])className=UserService(&|$)/ nocase
        $param1 = /(^|[?&;])methodName=isLogged(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_solarview_compact_pow_xss {
    meta:
        attack_type = "vuln_solarview_compact_pow_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SolarView Compact 6.00 - 'pow' Cross-Site Scripting: SolarView Compact version 6.00 contains a cross-site scripting vulnerability in the 'pow' parameter to Solar_SlideSub.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/solarview-compact-pow-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Solar_SlideSub\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])bgcolor=green(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_solarview_compact_time_begin_xss {
    meta:
        attack_type = "vuln_solarview_compact_time_begin_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SolarView Compact 6.00 - 'time_begin' Cross-Site Scripting: SolarView Compact version 6.00 contains a cross-site scripting vulnerability in the 'time_begin' parameter to Solar_History.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/solarview-compact-time-begin-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Solar_History\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_splash_render_ssrf {
    meta:
        attack_type = "vuln_splash_render_ssrf"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Splash Render - SSRF: Splash Render is vulnerable to Server-Side Request Forgery (SSRF) Vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/splash/splash-render-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/render\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_springblade_info_leak {
    meta:
        attack_type = "vuln_springblade_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SpringBlade - Information Leakage: SpringBlade is a comprehensive project upgraded and optimized from a commercial-grade project, featuring both a SpringCloud distributed microservice architecture and a SpringBoot monolithic microservice architecture. The SpringBlade framework."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/springblade-info-leak.yaml"
    strings:
        $path0 = /\/api\/blade-user\/user-list(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_springboot_actuators_jolokia_xxe {
    meta:
        attack_type = "vuln_springboot_actuators_jolokia_xxe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Spring Boot Actuators (Jolokia) XXE: A vulnerability in Spring Boot Actuators's 'jolokia' endpoint allows remote attackers to perform an XML External Entities (XXE) attack and include content stored on a remote server as if it was its own. This has the potential to allow the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/springboot/springboot-actuators-jolokia-xxe.yaml"
    strings:
        $path0 = /\/jolokia\/exec\/ch\.qos\.logback\.classic:Name=default,Type=ch\.qos\.logback\.classic\.jmx\.JMXConfigurator\/reloadByURL\/http:!\/!\/nonexistent:31337!\/logback\.xml(\/|;|$)/ nocase
        $path1 = /\/actuator\/jolokia\/exec\/ch\.qos\.logback\.classic:Name=default,Type=ch\.qos\.logback\.classic\.jmx\.JMXConfigurator\/reloadByURL\/http:!\/!\/random:915!\/logback\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_springboot_h2_db_rce {
    meta:
        attack_type = "vuln_springboot_h2_db_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Spring Boot H2 Database - Remote Command Execution: Spring Boot H2 Database is susceptible to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/springboot/springboot-h2-db-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/actuator\/env(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_squirrelmail_lfi {
    meta:
        attack_type = "vuln_squirrelmail_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SquirrelMail 1.2.11 - Local File Inclusion: SquirrelMail 1.2.11 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/squirrelmail/squirrelmail-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])mailbox=\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_squirrelmail_vkeyboard_xss {
    meta:
        attack_type = "vuln_squirrelmail_vkeyboard_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SquirrelMail Virtual Keyboard <=0.9.1 - Cross-Site Scripting: SquirrelMail Virtual Keyboard plugin 0.9.1 and prior contains a cross-site scripting vulnerability via the vkeyboard.php parameter. It fails to properly sanitize user-supplied input, which allows an attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/squirrelmail/squirrelmail-vkeyboard-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugins\/vkeyboard\/vkeyboard\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_sanhuismg_radius_rce {
    meta:
        attack_type = "vuln_sanhuismg_radius_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Synway SMG Gateway 9-2radius.php - Remote Command Execution: Synway SMG Gateway Management Software contains a remote command execution vulnerability in 9-2radius.php, where the radius_address parameter is passed to a system() call without sanitization. This allows."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/synway/synwaysmg-radius-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/en\/9-2radius\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_temenos_t24_xss {
    meta:
        attack_type = "vuln_temenos_t24_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Temenos T24 R20 - Cross-Site Scripting: Temenos T24 release 20 contains a reflected cross-site scripting vulnerability via the routineName parameter at genrequest.jsp. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/temenos-t24-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/jsps\/genrequest\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_temenos_transact_xss {
    meta:
        attack_type = "vuln_temenos_transact_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Temenos Transact - Cross-Site Scripting: Multiple vulnerabilities in Temenos Transact (formerly T24) that allows multiple reflected cross-site scripting (XSS) attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/temenos-transact-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/jsps\/helprequest\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_thinkcmf_lfi {
    meta:
        attack_type = "vuln_thinkcmf_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ThinkCMF - Local File Inclusion: ThinkCMF is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/thinkcmf/thinkcmf-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])templateFile=README\.md(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_thinkphp_501_rce {
    meta:
        attack_type = "vuln_thinkphp_501_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ThinkPHP 5.0.1 - Remote Code Execution: ThinkPHP 5.0.1 allows remote unauthenticated attackers to execute arbitrary code via the 's' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/thinkphp/thinkphp-501-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])filter\[\]=system(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_thinkphp_5023_rce {
    meta:
        attack_type = "vuln_thinkphp_5023_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ThinkPHP 5.0.23 - Remote Code Execution: ThinkPHP 5.0.23 is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/thinkphp/thinkphp-5023-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])filter\[\]=phpinfo(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tongda_action_uploadfile {
    meta:
        attack_type = "vuln_tongda_action_uploadfile"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tongda OA v2017 action_upload - Arbitrary File Upload: Tongda OA v2017 action_upload.php file filtering is insufficient and does not require background permissions, resulting in arbitrary file upload vulnerabilities"
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-action-uploadfile.yaml"
    strings:
        $path0 = /\/module\/ueditor\/php\/action_upload\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_api_file_upload {
    meta:
        attack_type = "vuln_tongda_api_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tongda OA v11.8 api.ali.php - Arbitrary File Upload: Tongda OA v11.8 api.ali.php has an arbitrary file upload vulnerability. An attacker can upload malicious files to control the server through the vulnerability."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-api-file-upload.yaml"
    strings:
        $path0 = /\/mobile\/api\/api\.ali\.php(\/|;|$)/ nocase
        $path1 = /\/inc\/package\/work\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_auth_bypass {
    meta:
        attack_type = "vuln_tongda_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA 11.7 - Authentication Bypass: Tongda OA is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., LTD v11.7 has the interface query online user function, when the user is online, it will return PHPSESSION so that it."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-auth-bypass.yaml"
    strings:
        $path0 = /\/mobile\/auth_mobi\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_contact_list_exposure {
    meta:
        attack_type = "vuln_tongda_contact_list_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tongda OA v2014 Get Contactlistt - Sensitive Information Disclosure: There is an information leakage vulnerability in the get_contactlist.php file of Tongda OA v2014. Attackers can obtain sensitive information through the vulnerability and conduct further attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-contact-list-exposure.yaml"
    strings:
        $path0 = /\/mobile\/inc\/get_contactlist\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_getdata_rce {
    meta:
        attack_type = "vuln_tongda_getdata_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tongda OA v11.9 getadata - Remote Code Execution: There is an arbitrary command execution vulnerability in the getdata interface of Tongda OA v11.9. An attacker can execute arbitrary commands on the server to control server permissions through the vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-getdata-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/general\/appbuilder\/web\/portal\/gateway\/getdata(\/|;|$)/ nocase
        $param0 = /(^|[?&;])module=Carouselimage(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tongda_getway_rfi {
    meta:
        attack_type = "vuln_tongda_getway_rfi"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tongda OA v11.8 getway.php - Remote File Inclution: There is a file inclusion vulnerability in Tongda OA v11.8 getway.php, an attacker sends a malicious request to include a log file, resulting in an arbitrary file writing vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-getway-rfi.yaml"
    strings:
        $path0 = /\/mac\/gateway\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_insert_sqli {
    meta:
        attack_type = "vuln_tongda_insert_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA v11.6 Insert Parameter - SQL Injection: Tongda OA v11.6 insert parameters contain SQL injection vulnerabilities, through which attackers can obtain sensitive database information"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-insert-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/general\/document\/index\.php\/recv\/register\/insert(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_login_code_authbypass {
    meta:
        attack_type = "vuln_tongda_login_code_authbypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA v11.8 logincheck_code.php - Authentication Bypass: There is a login bypass vulnerability in Tongda OA v11.8 logincheck_code.php, through which an attacker can log in to the system administrator background"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-login-code-authbypass.yaml"
    strings:
        $path0 = /\/general\/login_code\.php(\/|;|$)/ nocase
        $path1 = /\/logincheck_code\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_meeting_unauth {
    meta:
        attack_type = "vuln_tongda_meeting_unauth"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tongda OA Meeting - Unauthorized Access: Tongda Meeting Unauthorized Access were Detected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-meeting-unauth.yaml"
    strings:
        $path0 = /\/general\/calendar\/arrange\/get_cal_list\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])view=agendaDay(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tongda_oa_swfupload_sqli {
    meta:
        attack_type = "vuln_tongda_oa_swfupload_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA v11.5 swfupload_new.php - SQL Injection: There is a SQL injection vulnerability in the swfupload_new.php file of Tongda OA v11.5. An attacker can obtain sensitive information of the server through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-oa-swfupload-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/general\/file_folder\/swfupload_new\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_report_func_sqli {
    meta:
        attack_type = "vuln_tongda_report_func_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA v11.6 report_bi.func.php - SQL injection: Tongda OA v11.6 report_bi.func.php has a SQL injection vulnerability, and attackers can obtain database information through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-report-func-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/general\/bi_design\/appcenter\/report_bi\.func\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_session_disclosure {
    meta:
        attack_type = "vuln_tongda_session_disclosure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tongda User Session Disclosure: Tongda User session exposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-session-disclosure.yaml"
    strings:
        $path0 = /\/general\/userinfo\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_tongda_video_file_read {
    meta:
        attack_type = "vuln_tongda_video_file_read"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tongda OA V2017 Video File - Arbitrary File Read: There is an arbitrary file reading vulnerability in Extreme OA video_file.php. An attacker can obtain sensitive files on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongda-video-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/general\/mytable\/intel_view\/video_file\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])MEDIA_DIR=\.\.\/\.\.\/\.\.\/inc\/(&|$)/ nocase
        $param1 = /(^|[?&;])MEDIA_NAME=oa_config\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tongdaoa_auth_bypass {
    meta:
        attack_type = "vuln_tongdaoa_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tongda OA - Authentication Bypass: Tongda OA is an OA system. The old version of header.inc.php has an authentication bypass vulnerability. An attacker can construct a malicious request to access header.inc.php, obtain the cookie, pass identity authentication, log in to the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tongda/tongdaoa-auth-bypass.yaml"
    strings:
        $path0 = /\/module\/retrieve_pwd\/header\.inc\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_topsec_topacm_rce {
    meta:
        attack_type = "vuln_topsec_topacm_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Topsec Topacm - Remote Code Execution: Tianrongxin Internet Behavior Management System static_convert.php remote command execution vulnerability"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/topsec/topsec-topacm-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/view\/IPV6\/naborTable\/static_convert\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_topsec_topapplb_auth_bypass {
    meta:
        attack_type = "vuln_topsec_topapplb_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Topsec TopAppLB - Authentication Bypass: Topsec TopAppLB is vulnerable to authetication bypass .Enter any account on the login page, the password is `;id`."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/topsec/topsec-topapplb-auth-bypass.yaml"
    strings:
        $path0 = /\/login_check\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_totolink_boaform_rce {
    meta:
        attack_type = "vuln_totolink_boaform_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TOTOLink Router - Remote Command Execution: TOTOLink routers are vulnerable to unauthenticated remote command execution via the /boaform/formWsc endpoint. An attacker can inject OS commands through the localPin parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/totolink-boaform-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/boaform\/formWsc(\/|;|$)/ nocase
        $param0 = /(^|[?&;])targetAPMac=001A2B3C4D5E(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_tp_link_wr840n_auth_bypass {
    meta:
        attack_type = "vuln_tp_link_wr840n_auth_bypass"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TP-LINK WR840N v6 up to 0.9.1 4.16 - Improper Authentication: A vulnerability in the TP-Link WR840N v6 router with firmware version 0.9.1 4.16 and earlier permits unauthorized individuals to bypass the authentication of some interfaces under the /cgi directory.When adding."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/tp-link-wr840n-auth-bypass.yaml"
    strings:
        $path0 = /\/cgi\/getParm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ueditor_ssrf {
    meta:
        attack_type = "vuln_ueditor_ssrf"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "UEditor - Server Side Request Forgery: UEditor contains an Server Side Request Forgery vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/ueditor/ueditor-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/ueditor\/jsp\/controller\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ueditor_arbitrary_file_upload {
    meta:
        attack_type = "vuln_ueditor_arbitrary_file_upload"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "UEditor - PHP Arbitrary File Upload: Detects arbitrary file upload vulnerability in UEditor PHP by attempting to upload and execute a PHP file. This vulnerability allows remote attackers to upload arbitrary files including PHP files, potentially leading to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/ueditor-arbitrary-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=uploadimage(&|$)/ nocase
        $param1 = /(^|[?&;])CONFIG\[imageAllowFiles\]\[\]=\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_una_cms_rce {
    meta:
        attack_type = "vuln_una_cms_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UNA CMS <= 14.0.0-RC4 - PHP Object Injection: The vulnerability is located in the /template/scripts/BxBaseMenuSetAclLevel.php script. Specifically, within the BxBaseMenuSetAclLevel::getCode() method. When calling this method, user input passed through the 'profile_id' POST."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/una-cms-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cache_public\/sh\.phtml(\/|;|$)/ nocase
        $path1 = /\/cache_public\/sh\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])a=SetAclLevel(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_arcade_php_sqli {
    meta:
        attack_type = "vuln_arcade_php_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Arcade.php - SQL Injection: The arcade.php script is vulnerable to SQL injection. By exploiting this vulnerability, an attacker can manipulate the SQL queries executed by the script, potentially gaining unauthorized access to the database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vbulletin/arcade-php-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/arcade\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vbulletin_backdoor {
    meta:
        attack_type = "vuln_vbulletin_backdoor"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "vBulletin Backdoor - Detect"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vbulletin/vbulletin-backdoor.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/forum\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vicidial_info_disclosure {
    meta:
        attack_type = "vuln_vicidial_info_disclosure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VICIdial Sensitive Information Disclosure: VICIdial's Web Client is susceptible to information disclosure because it contains many sensitive files that can be accessed from the client side. These files contain mysqli logs, auth logs, debug information, successful and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vicidial-info-disclosure.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/agc\/vicidial_mysqli_errors\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vmware_cloud_xss {
    meta:
        attack_type = "vuln_vmware_cloud_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "VMWare Cloud - Cross Site Scripting: VMWare Cloud is vulnerable to Reflected Cross Site Scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vmware/vmware-cloud-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])redirectTo=\/tenant\/e(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_vmware_nsx_stream_rce {
    meta:
        attack_type = "vuln_vmware_nsx_stream_rce"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VMware NSX Manager XStream Pre-authenticated Remote Code Execution: VMware Cloud Foundation (NSX-V) contains a remote code execution vulnerability via XStream open source library. VMware has evaluated the severity of this issue to be in the Critical severity range with a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vmware/vmware-nsx-stream-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/2.0/services/usermgmt/password/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vmware_vcenter_log4j_rce {
    meta:
        attack_type = "vuln_vmware_vcenter_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware VCenter - Remote Code Execution (Apache Log4j): VMware VCenter is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vmware/vmware-vcenter-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/websso\/SAML2\/SSO\/vsphere\.local(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vmware_vcenter_ssrf {
    meta:
        attack_type = "vuln_vmware_vcenter_ssrf"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware vCenter - Server-Side Request Forgery/Local File Inclusion/Cross-Site Scripting: VMware vCenter 7.0.2.00100 is susceptible to multiple vulnerabilities including server-side request forgery, local file inclusion, and cross-site scripting."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vmware/vmware-vcenter-ssrf.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ui\/vcav-bootstrap\/rest\/vcav-providers\/provider-logo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vrealize_operations_log4j_rce {
    meta:
        attack_type = "vuln_vrealize_operations_log4j_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware vRealize Operations Tenant - JNDI Remote Code Execution (Apache Log4j): VMware vRealize Operations is susceptible to a critical vulnerability in Apache Log4j which may allow remote code execution in an impacted vRealize Operations Tenant application."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/vmware/vrealize-operations-log4j-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/suite-api\/api\/auth\/token\/acquire(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhu_download_ftp_file_read {
    meta:
        attack_type = "vuln_wanhu_download_ftp_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wanhu OA download_ftp.jsp - Arbitrary File Read: There is an arbitrary file download vulnerability in the Wanhu OA download_ftp.jsp file. An attacker can download any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhu-download-ftp-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/defaultroot\/download_ftp\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhu_download_old_file_read {
    meta:
        attack_type = "vuln_wanhu_download_old_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wanhu OA download_old.jsp - Arbitrary File Read: There is an arbitrary file download vulnerability in the Wanhu OA download_old.jsp file. An attacker can download any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhu-download-old-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/defaultroot\/download_old\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhu_oa_fileupload_controller {
    meta:
        attack_type = "vuln_wanhu_oa_fileupload_controller"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wanhu OA Fileupload Controller - Arbitrary File Upload: There is an arbitrary file upload vulnerability in Wanhu OA fileUpload.controller. An attacker can upload any file through the vulnerability."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhu-oa-fileupload-controller-arbitrary-file-upload.yaml"
    strings:
        $path0 = /\/defaultroot\/upload\/fileUpload\.controller(\/|;|$)/ nocase
        $path1 = "/defaultroot/upload/html/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhu_teleconferenceservice_xxe {
    meta:
        attack_type = "vuln_wanhu_teleconferenceservice_xxe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wanhu OA TeleConferenceService Interface - XML External Entity Injection: There is an XXE injection vulnerability in the Wanhu OA TeleConferenceService interface. An attacker can use the vulnerability to continue XXE injection to obtain sensitive information on the server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhu-teleconferenceservice-xxe.yaml"
    strings:
        $path0 = /\/defaultroot\/iWebOfficeSign\/OfficeServer\.jsp\/\.\.\/\.\.\/TeleConferenceService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhuoa_downloadservlet_lfi {
    meta:
        attack_type = "vuln_wanhuoa_downloadservlet_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wanhu OA DownloadServlet - Remote File Disclosure: There is an arbitrary file reading vulnerability in the Wanhu OA DownloadServlet interface. An attacker can use the vulnerability to read sensitive files in the server and obtain sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhuoa-downloadservlet-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/defaultroot\/DownloadServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])FileName=WEB-INF\/classes\/fc\.properties(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wanhuoa_officeserverservlet_file_upload {
    meta:
        attack_type = "vuln_wanhuoa_officeserverservlet_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wanhu OA OfficeServerServlet - Arbitrary File Upload: Wanhu OA officeserverservlet file upload vulnerability"
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhuoa-officeserverservlet-file-upload.yaml"
    strings:
        $path0 = /\/defaultroot\/officeserverservlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wanhuoa_smartupload_file_upload {
    meta:
        attack_type = "vuln_wanhuoa_smartupload_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wanhu OA smartUpload.jsp - Arbitrary File Upload: Wanhu OA smartUpload.jsp file has a file upload interface and does not filter file types, resulting in arbitrary file upload vulnerabilities. Malicious JSP files can be uploaded directly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wanhu/wanhuoa-smartupload-file-upload.yaml"
    strings:
        $path0 = /\/defaultroot\/extension\/smartUpload\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])path=information(&|$)/ nocase
        $param1 = /(^|[?&;])fileName=infoPicName(&|$)/ nocase
        $param2 = /(^|[?&;])saveName=infoPicSaveName(&|$)/ nocase
        $param3 = /(^|[?&;])tableName=infoPicTable(&|$)/ nocase
        $param4 = /(^|[?&;])fileType=gif,jpg,bmp,jsp,png(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ecology_arbitrary_file_upload {
    meta:
        attack_type = "vuln_ecology_arbitrary_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ecology - Arbitrary File Upload: Ecology contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-arbitrary-file-upload.yaml"
    strings:
        $path0 = "/page/exportImport/fileTransfer/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ecology_execforstr_rce {
    meta:
        attack_type = "vuln_ecology_execforstr_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Weaver Ecology ExecForStr Remote Command Execution: Weaver Ecology exposes a debug API endpoint that allows invocation of `cn.hutool.core.util.RuntimeUtil.execForStr`, resulting in remote command execution. Successful exploitation allows an attacker to execute arbitrary."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-execforstr-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/papi\/esearch\/data\/devops\/dubboApi\/debug\/method(\/|;|$)/ nocase
        $param0 = /(^|[?&;])interfaceName=cn\.hutool\.core\.util\.RuntimeUtil(&|$)/ nocase
        $param1 = /(^|[?&;])methodName=execForStr(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ecology_filedownload_directory_traversal {
    meta:
        attack_type = "vuln_ecology_filedownload_directory_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ecology - Local File Inclusion: Ecology is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-filedownload-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/weaver\/ln\.FileDownload(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fpath=\.\.\/ecology\/WEB-INF\/web\.xml(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ecology_oa_byxml_xxe {
    meta:
        attack_type = "vuln_ecology_oa_byxml_xxe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "EcologyOA deleteUserRequestInfoByXml - XML External Entity Injection: EcologyOA deleteUserRequestInfoByXml interface has XXE"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-oa-byxml-xxe.yaml"
    strings:
        $path0 = /\/rest\/ofs\/deleteUserRequestInfoByXml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ecology_springframework_directory_traversal {
    meta:
        attack_type = "vuln_ecology_springframework_directory_traversal"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ecology Springframework - Local File Inclusion: Ecology Springframework is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-springframework-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/weaver\/org\.springframework\.web\.servlet\.ResourceServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ecology_syncuserinfo_sqli {
    meta:
        attack_type = "vuln_ecology_syncuserinfo_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ecology Syncuserinfo - SQL Injection: Ecology Syncuserinfo contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology/ecology-syncuserinfo-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/mobile\/plugin\/SyncUserInfo\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ecology_jqueryfiletree_traversal {
    meta:
        attack_type = "vuln_ecology_jqueryfiletree_traversal"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Weaver E-Cology JqueryFileTree - Directory Traversal: Panwei OA E-Cology jqueryFileTree.jsp directory traversal vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology-jqueryfiletree-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/hrm\/hrm_e9\/orgChart\/js\/jquery\/plugins\/jqueryFileTree\/connectors\/jqueryFileTree\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dir=\/page\/resource\/userfile\/\.\.\/\.\.\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ecology_verifyquicklogin_auth_bypass {
    meta:
        attack_type = "vuln_ecology_verifyquicklogin_auth_bypass"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver e-cology verifyquicklogin.jsp - Auth Bypass: There is an arbitrary administrator login vulnerability in the Panwei OA E-Cology VerifyQuickLogin.jsp file. An attacker can obtain the administrator Session by sending a special request package."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/ecology-verifyquicklogin-auth-bypass.yaml"
    strings:
        $path0 = /\/mobile\/plugin\/VerifyQuickLogin\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ipaddress=x\.x\.x\.x(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_eoffice_file_upload {
    meta:
        attack_type = "vuln_weaver_eoffice_file_upload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-Office v9.5 - Arbitrary File Upload: Weaver E-Office version 9.5 is susceptible to an arbitrary file upload vulnerability. This flaw allows malicious actors to upload and execute arbitrary code or files without proper validation or authorization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/eoffice/weaver-eoffice-file-upload.yaml"
    strings:
        $path0 = /\/E-mobile\/App\/Ajax\/ajax\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_oa_v9_uploads_file {
    meta:
        attack_type = "vuln_oa_v9_uploads_file"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA 9 - Arbitrary File Upload: OA 9 is susceptible to arbitrary file upload via the uploadOperation.jsp endpoint. These files can be subsequently called and are executed by the remote software, and an attacker can obtain sensitive information, modify data, and/or gain full."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/oa-v9-uploads-file.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/page\/exportImport\/fileTransfer\/poc\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_checkserver_sqli {
    meta:
        attack_type = "vuln_weaver_checkserver_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ecology OA CheckServer - SQL Injection: Ecology OA system improperly filters incoming data from users, resulting in a SQL injection vulnerability. Remote and unauthenticated attackers can use this vulnerability to conduct SQL injection attacks and steal sensitive database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-checkserver-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/mobile\/plugin\/CheckServer\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=mobileSetting(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_e_cology_validate_sqli {
    meta:
        attack_type = "vuln_weaver_e_cology_validate_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver e-cology Validate.JSP - SQL Injection: In the validate.jsp file of the Panwei e-cology OA system, the parameter capitalid is not strictly filtered, which can lead to SQL injection vulnerabilities. An attacker can use this vulnerability to remotely send carefully."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-e-cology-validate-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/cpt\/manage\/validate\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sourcestring=validateNum(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_e_mobile_rce {
    meta:
        attack_type = "vuln_weaver_e_mobile_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Weaver E-mobile client.do - Remote Code Execution: E-Mobile 6.0 has a command execution vulnerability. It has now been confirmed that this vulnerability can be exploited by an attacker. In some cases, user input may be passed directly to the command execution function of the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-e-mobile-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/client\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_ebridge_lfi {
    meta:
        attack_type = "vuln_weaver_ebridge_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-Bidge saveYZJFile - Local File Read: There is an arbitrary file reading vulnerability in the Weaver OA E-Bridge saveYZJFile interface. An attacker can read any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-ebridge-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wxjsapi\/saveYZJFile(\/|;|$)/ nocase
        $path1 = "/file/fileNoLogin/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_ecology_bshservlet_rce {
    meta:
        attack_type = "vuln_weaver_ecology_bshservlet_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Weaver E-Cology BeanShell - Remote Command Execution: Weaver BeanShell contains a remote command execution vulnerability in the bsh.servlet.BshServlet program."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-ecology-bshservlet-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/weaver\/bsh\.servlet\.BshServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_ecology_getsqldata_sqli {
    meta:
        attack_type = "vuln_weaver_ecology_getsqldata_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-Cology `getsqldata` - SQL Injection: When the getSqlData interface of the Panwei e-cology OA system uses the mssql database, the built-in SQL statements are not spliced strictly, resulting in a SQL injection vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-ecology-getsqldata-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/Api\/portal\/elementEcodeAddon\/getSqlData(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_ecology_hrmcareer_sqli {
    meta:
        attack_type = "vuln_weaver_ecology_hrmcareer_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-Cology HrmCareerApplyPerView - SQL Injection: There is a SQL injection vulnerability in the HrmCareerApplyPerView.jsp file of Panwei OA E-Cology. An attacker can obtain sensitive files in the server database through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-ecology-hrmcareer-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/pweb\/careerapply\/HrmCareerApplyPerView\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_ecology9_doc_list_sqli {
    meta:
        attack_type = "vuln_weaver_ecology9_doc_list_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-cology9 api/doc/out/more/list SQL Injection: Weaver E-cology9 contains a SQL injection vulnerability in the `/api/doc/out/more/list` endpoint. A crafted request can trigger backend SQL execution and generate a temporary `sessionkey`, which can subsequently be used with."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-ecology9-doc-list-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/ec\/dev\/table\/counts(\/|;|$)/ nocase
        $param0 = /(^|[?&;])docarchivedatefrom=a'OR-1\/\*a(&|$)/ nocase
        $param1 = /(^|[?&;])doccreatedatefrom=\*\/=\(\/\*a(&|$)/ nocase
        $param2 = /(^|[?&;])doclastmoddatefrom=\*\/SELECT-3\+locate\/\*(&|$)/ nocase
        $param3 = /(^|[?&;])docarchivedateto=\*\/\(hex\(SUBSTRING\(\/\*(&|$)/ nocase
        $param4 = /(^|[?&;])doclastmoddateto=\*\/from HrmResourceManager limit 0,1\) OR-1\/\*(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_getemdslist_disclosure {
    meta:
        attack_type = "vuln_weaver_getemdslist_disclosure"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver E-cology getEmDsList Sensitive Information Disclosure: Weaver E-cology10 contains a sensitive information disclosure vulnerability in the `/papi/em/transform/getEmDsList` endpoint. An unauthenticated attacker can access the endpoint to retrieve datasource-related."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-getemdslist-disclosure.yaml"
    strings:
        $path0 = /\/papi\/em\/transform\/getEmDsList(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_group_xml_sqli {
    meta:
        attack_type = "vuln_weaver_group_xml_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OA E-Office group_xml.php - SQL Injection: There is a SQL injection vulnerability in the Panwei OA E-Office group_xml.php file. Through the vulnerability, an attacker can write to the Webshell file to obtain server permissions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-group-xml-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/inc\/group_user_list\/group_xml\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_lazyuploadify_file_upload {
    meta:
        attack_type = "vuln_weaver_lazyuploadify_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OA E-Office LazyUploadify - Arbitrary File Upload: OA E-Office LazyUploadify is vulnerable to arbitrary file upload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-lazyuploadify-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/general\/weibo\/javascript\/LazyUploadify\/uploadify\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_login_sessionkey {
    meta:
        attack_type = "vuln_weaver_login_sessionkey"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA E-Mobile login_quick.php - Login SessionKey: login_quick.php in OA E-Mobile leaks session key."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-login-sessionkey.yaml"
    strings:
        $path0 = /\/E-mobile\/App\/System\/Login\/login_quick\.php(\/|;|$)/ nocase
        $path1 = /\/E-mobile\/App\/Init\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_office_server_file_upload {
    meta:
        attack_type = "vuln_weaver_office_server_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OA E-Office OfficeServer.php Arbitrary File Upload: OA E-Office OfficeServer.php has an arbitrary file upload vulnerability. Attackers can obtain sensitive information on the server through the vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-office-server-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/eoffice10\/server\/public\/iWebOffice2015\/OfficeServer\.php(\/|;|$)/ nocase
        $path1 = "/eoffice10/server/public/iWebOffice2015/Document/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_officeserver_lfi {
    meta:
        attack_type = "vuln_weaver_officeserver_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA E-Office officeserver.php Arbitrary File Read: There is an arbitrary file reading vulnerability in the OA E-Office officeserver.php file. An attacker can download any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-officeserver-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/iweboffice\/officeserver\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])OPTION=LOADFILE(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_signaturedownload_lfi {
    meta:
        attack_type = "vuln_weaver_signaturedownload_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA E-Weaver SignatureDownLoad - Arbitrary File Read: There is an arbitrary file reading vulnerability in the E-Weaver SignatureDownLoad interface of Panwei OA. An attacker can read any file on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-signaturedownload-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/weaver\/weaver\.file\.SignatureDownLoad(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_sptmforportalthumbnail_lfi {
    meta:
        attack_type = "vuln_weaver_sptmforportalthumbnail_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA E-Weaver SptmForPortalThumbnail - Arbitrary File Read: The controllable preview parameters of SptmForPortalThumbnail.jsp are not filtered and are directly spliced to the web root directory for file downloading."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-sptmforportalthumbnail-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/portal\/SptmForPortalThumbnail\.jsp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])preview=portal\/SptmForPortalThumbnail\.jsp(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weaver_uploadify_file_upload {
    meta:
        attack_type = "vuln_weaver_uploadify_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OA E-Office Uploadify - Arbitrary File Upload: OA E-Office Uploadify is vulnerable to arbitrary file upload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-uploadify-file-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/general\/weibo\/javascript\/uploadify\/uploadify\.php(\/|;|$)/ nocase
        $path1 = /\/attachment\/personal\/_temp\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_uploadoperation_file_upload {
    meta:
        attack_type = "vuln_weaver_uploadoperation_file_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Weaver OA Workrelate - Arbitary File Upload: Ecology contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-uploadoperation-file-upload.yaml"
    strings:
        $path0 = /\/workrelate\/plan\/util\/uploaderOperate\.jsp(\/|;|$)/ nocase
        $path1 = /\/OfficeServer(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_weaver_userselect_unauth {
    meta:
        attack_type = "vuln_weaver_userselect_unauth"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OA E-Office UserSelect Unauthorized Access: OA E-Office UserSelect interface has an unauthorized access vulnerability, through which attackers can obtain sensitive information"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/weaver/weaver-userselect-unauth.yaml"
    strings:
        $path0 = "/UserSelect/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wechat_info_leak {
    meta:
        attack_type = "vuln_wechat_info_leak"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WeChat agentinfo - Information Exposure: There is an information leakage vulnerability in the agentinfo interface of Tencent Enterprise WeChat. An attacker can obtain the Enterprise WeChat Secret through the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wechat/wechat-info-leak.yaml"
    strings:
        $path0 = /\/cgi-bin\/gateway\/agentinfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_3d_print_lite_xss {
    meta:
        attack_type = "vuln_3d_print_lite_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "3D Print Lite < 1.9.1.6 - Reflected Cross-Site Scripting: The plugin does not sanitise and escape some user input before outputting it back in attributes, leading to Reflected Cross-Site Scripting issues"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/3d-print-lite-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=p3dlite_materials(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ad_widget_lfi {
    meta:
        attack_type = "vuln_ad_widget_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Ad Widget 2.11.0 - Local File Inclusion: WordPress Ad Widget 2.11.0 is vulnerable to local file inclusion. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/ad-widget-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/ad-widget/views/modal/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_advanced_access_manager_lfi {
    meta:
        attack_type = "vuln_advanced_access_manager_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Advanced Access Manager < 5.9.9 - Local File Inclusion: WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/advanced-access-manager-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])aam-media=wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_advanced_booking_calendar_sqli {
    meta:
        attack_type = "vuln_advanced_booking_calendar_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Advanced Booking Calendar < 1.6.2 - SQL Injection: The AJAX action abc_booking_getBookingResult, available to both authenticated and Unauthenticated users did not sanitise the calendarId parameter which was then concatenated to a SQL statement, leading an unauthenticated SQL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/advanced-booking-calendar-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])calendarId=1\) AND \(SELECT 2065 FROM \(SELECT\(SLEEP\(6\)\)\)jtGw\) AND \(5440=5440(&|$)/ nocase
        $param1 = /(^|[?&;])action=abc_booking_getBookingResult(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_age_gate_open_redirect {
    meta:
        attack_type = "vuln_age_gate_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Age Gate <2.13.5 - Open Redirect: WordPress Age Gate plugin before 2.13.5 contains an open redirect vulnerability via the _wp_http_referer parameter after certain actions and after invalid or missing nonces. An attacker can redirect a user to a malicious site and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/age-gate-open-redirect.yaml"
    strings:
        $param0 = /(^|[?&;])age_gate\[age\]=TVRnPQ==(&|$)/ nocase
        $param1 = /(^|[?&;])age_gate\[nonce\]=48f2b89fed(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_ait_csv_import_export_rce {
    meta:
        attack_type = "vuln_ait_csv_import_export_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress AIT CSV Import Export - Unauthenticated Remote Code Execution: The AIT CSV Import/Export plugin <= 3.0.3 allows unauthenticated remote attackers to upload and execute arbitrary PHP code. The upload-handler does not require authentication, nor validates the uploaded."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/ait-csv-import-export-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-content\/plugins\/ait-csv-import-export\/admin\/upload-handler\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_alfacgiapi_wordpress {
    meta:
        attack_type = "vuln_alfacgiapi_wordpress"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Searches for sensitive directories present in the alfacgiapi plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/alfacgiapi-wordpress.yaml"
    strings:
        $path0 = "/wp-content/uploads/alm_templates/ALFA_DATA/alfacgiapi/" ascii nocase
        $path1 = "/ALFA_DATA/alfacgiapi/" ascii nocase
        $path2 = "/cgi-bin/ALFA_DATA/alfacgiapi/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_amministrazione_aperta_lfi {
    meta:
        attack_type = "vuln_amministrazione_aperta_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Amministrazione Aperta 3.7.3 - Local File Inclusion: WordPress Amministrazione Aperta 3.7.3 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/amministrazione-aperta-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/amministrazione-aperta\/wpgov\/dispatcher\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_application_pass_xss {
    meta:
        attack_type = "vuln_application_pass_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Core 5.6 and 6.3.1 - Cross-Site Scripting: WordPress Core is vulnerable to Reflected Cross-Site Scripting via the 'success_url' and 'reject_url' parameters when requesting application passwords in versions between 5.6 and 6.3.1 due to insufficient input sanitization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/application-pass-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-admin\/authorize-application\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])success_url=javascript:alert\(document\.domain\)(&|$)/ nocase
        $param1 = /(^|[?&;])reject_url=javascript:alert\(document\.domain\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_aspose_file_download {
    meta:
        attack_type = "vuln_aspose_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress Aspose Cloud eBook Generator - Local File Inclusion: Wordpress Aspose Cloud eBook Generator is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/aspose-file-download.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/aspose-cloud-ebook-generator\/aspose_posts_exporter_download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aspose_ie_file_download {
    meta:
        attack_type = "vuln_aspose_ie_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Aspose Importer & Exporter 1.0 - Local File Inclusion: WordPress Aspose Importer & Exporter version 1.0 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/aspose-ie-file-download.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/aspose-importer-exporter\/aspose_import_export_download(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aspose_pdf_file_download {
    meta:
        attack_type = "vuln_aspose_pdf_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Aspose PDF Exporter - Local File Inclusion: WordPress Aspose PDF Exporter is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/aspose-pdf-file-download.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/Wordpress\/Aaspose-pdf-exporter\/aspose_pdf_exporter_download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_aspose_words_file_download {
    meta:
        attack_type = "vuln_aspose_words_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Aspose Words Exporter <2.0 - Local File Inclusion: WordPress Aspose Words Exporter prior to version 2.0 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/aspose-words-file-download.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/aspose-doc-exporter\/aspose_doc_exporter_download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_attitude_theme_open_redirect {
    meta:
        attack_type = "vuln_attitude_theme_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Attitude 1.1.1 - Open Redirect: WordPress Attitude theme 1.1.1 contains an open redirect vulnerability via the goto.php endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/attitude-theme-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/Attitude\/go\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_avchat_video_chat_xss {
    meta:
        attack_type = "vuln_avchat_video_chat_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting: WordPress AVChat Video Chat 1.4.1 is vulnerable to reflected cross-site scripting via index_popup.php and multiple parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/avchat-video-chat-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/avchat-3\/index_popup\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_blog_designer_pack_rce {
    meta:
        attack_type = "vuln_blog_designer_pack_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "News & Blog Designer Pack < 3.4.2 - Remote Code Execution: News & Blog Designer Pack contains a local file inclusion vulnerability via user controlled $design variable extracted by POST parameter 'shrt_param' leading to Remote Code Execution via pearcmd.php. The vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/blog-designer-pack-rce.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])shrt_param\[design\]=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/local\/lib\/php\/pearcmd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_calameo_publications_xss {
    meta:
        attack_type = "vuln_calameo_publications_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting: WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via thickbox_content.php and the attachment_id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/calameo-publications-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/athlon-manage-calameo-publications\/thickbox_content\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_checkout_fields_manager_xss {
    meta:
        attack_type = "vuln_checkout_fields_manager_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Checkout Fields Manager for WooCommerce <5.5.7 - Cross-Site Scripting: WordPress Checkout Fields Manager for WooCommerce 5.5.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/checkout-fields-manager-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])section=advanced(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_church_admin_lfi {
    meta:
        attack_type = "vuln_church_admin_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Church Admin 0.33.2.1 - Local File Inclusion: WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the 'key' parameter of plugins/church-admin/display/download.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/church-admin-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/church-admin\/display\/download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_churchope_lfi {
    meta:
        attack_type = "vuln_churchope_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress ChurcHope Theme <= 2.1 - Local File Inclusion: WordPress ChurcHope Theme <= 2.1 is susceptible to local file inclusion. The vulnerability is caused by improper filtration of user-supplied input passed via the 'file' HTTP GET parameter to the '/lib/downloadlink.php'."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/churchope-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/themes\/churchope\/lib\/downloadlink\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_clearfy_cache_xss {
    meta:
        attack_type = "vuln_clearfy_cache_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Clearfy Cache <2.0.5 - Cross-Site Scripting: WordPress Clearfy Cache 2.0.5 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/clearfy-cache-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=gonzales-wbcr_clearfy(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_diarise_theme_lfi {
    meta:
        attack_type = "vuln_diarise_theme_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Diarise 1.5.9 - Arbitrary File Retrieval: WordPress Diarise theme version 1.5.9 suffers from a local file retrieval vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/diarise-theme-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/themes\/diarise\/download\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])calendar=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_easy_media_gallery_pro_listing {
    meta:
        attack_type = "vuln_easy_media_gallery_pro_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Media Gallery Pro Listing: Searches for sensitive directories present in the easy-media-gallery-pro plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/easy-media-gallery-pro-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/easy-media-gallery-pro/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_eatery_restaurant_open_redirect {
    meta:
        attack_type = "vuln_eatery_restaurant_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Eatery 2.2 - Open Redirect: WordPress Eatery theme 2.2 contains an open redirect vulnerability. The theme accepts a user-controlled input that specifies a link to an external site. An attacker can redirect a user to a malicious site and possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/eatery-restaurant-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/eatery\/nav\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_elex_woocommerce_xss {
    meta:
        attack_type = "vuln_elex_woocommerce_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WooCommerce Google Shopping < 1.2.4 - Cross-Site Scripting: WordPress WooCommerce Google Shopping < 1.2.4 is susceptible to cross-site scripting because the plugin does not sanitize or escape the search GET parameter before outputting it back in the page and executing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/elex-woocommerce-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=elex-product-feed-manage(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_hb_audio_lfi {
    meta:
        attack_type = "vuln_hb_audio_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress HB Audio Gallery Lite - Local File Inclusion: Wordpress HB Audio Gallery Lite is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/hb-audio-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/hb-audio-gallery-lite\/gallery\/audio-download\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file_path=\.\.\/\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_hide_security_enhancer_lfi {
    meta:
        attack_type = "vuln_hide_security_enhancer_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Hide Security Enhancer 1.3.9.2 Local File Inclusion: WordPress Hide Security Enhancer version 1.3.9.2 or less is susceptible to a local file inclusion vulnerability which could allow malicious visitors to download any file in the installation."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/hide-security-enhancer-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-hide-security-enhancer\/router\/file-process\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file_path=\/wp-config\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_issuu_panel_lfi {
    meta:
        attack_type = "vuln_issuu_panel_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress Plugin Issuu Panel Remote/Local File Inclusion: The WordPress Issuu Plugin includes an arbitrary file disclosure vulnerability that allows unauthenticated attackers to disclose the content of local and remote files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/issuu-panel-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/issuu-panel\/menu\/documento\/requests\/ajax-docs\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])abspath=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_jetpack_stored_xss {
    meta:
        attack_type = "vuln_jetpack_stored_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jetpack < 6.5 - Stored Cross-Site Scripting: Detected authenticated stored XSS in Jetpack < 6.5 via crafted Gist shortcode."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/jetpack-gist-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_title=XSS Test(&|$)/ nocase
        $param1 = /(^|[?&;])hidden_post_visibility=public(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_knr_widget_xss {
    meta:
        attack_type = "vuln_knr_widget_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "KNR Author List Widget - Cross-site Scripting: KNR Author List Widget suffers from Cross-site Scripting (XSS) in the listItem[] parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/knr-widget-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/knr-author-list-widget\/knrAuthorListCustomSortSave\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_ldap_wp_login_xss {
    meta:
        attack_type = "vuln_ldap_wp_login_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ldap WP Login / Active Directory Integration < 3.0.2 - Cross-Site Scripting: The plugin does not escape generated URLs before outputing them in attrubutes, leading to Reflected Cross-Site Scripting"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/ldap-wp-login-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=LDAP authentication intergrating with AD(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_members_list_xss {
    meta:
        attack_type = "vuln_members_list_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Members List <4.3.7 - Cross-Site Scripting: WordPress Members List 4.3.7 does not sanitize and escape some parameters in various pages before outputting them back, leading to reflected cross-site scripting vulnerabilities."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/members-list-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/members-list\/admin\/view\/user\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_modula_image_gallery_xss {
    meta:
        attack_type = "vuln_modula_image_gallery_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Modula Image Gallery <2.6.7 - Cross-Site Scripting: WordPress Modula Image Gallery 2.6.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/modula-image-gallery-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=modula-gallery(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_music_store_open_redirect {
    meta:
        attack_type = "vuln_music_store_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress eCommerce Music Store <=1.0.14 - Open Redirect: WordPress eCommerce Music Store plugin through 1.0.14 contains an open redirect vulnerability via the referer header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/music-store-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/music-store\/ms-core\/ms-submit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_my_chatbot_xss {
    meta:
        attack_type = "vuln_my_chatbot_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress My Chatbot <= 1.1 - Cross-Site Scripting: WordPress My Chatbot <= 1.1 is susceptible to cross-site scripting. The plugin does not sanitize or escape its tab parameter in the Settings page before outputting it back in an attribute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/my-chatbot-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=my-chatbot(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_nativechurch_wp_theme_lfd {
    meta:
        attack_type = "vuln_nativechurch_wp_theme_lfd"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress NativeChurch Theme - Local File Inclusion: WordPress NativeChurch Theme is vulnerable to local file inclusion in the download.php file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/nativechurch-wp-theme-lfd.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/themes\/NativeChurch\/download\/download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_newsletter_open_redirect {
    meta:
        attack_type = "vuln_newsletter_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Newsletter Manager < 1.5 - Unauthenticated Open Redirect: WordPress Newsletter Manager < 1.5 is susceptible to an open redirect vulnerability. The plugin used base64 encoded user input in the appurl parameter without validation to redirect users using the header() PHP."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/newsletter-open-redirect.yaml"
    strings:
        $param0 = /(^|[?&;])wp_nlm=confirmation(&|$)/ nocase
        $param1 = /(^|[?&;])appurl=aHR0cDovL2ludGVyYWN0LnNo(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_photoblocks_grid_gallery_xss {
    meta:
        attack_type = "vuln_photoblocks_grid_gallery_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gallery Photoblocks < 1.1.41 - Cross-Site Scripting: Reflected Cross-Site Scripting (XSS) is a type of web vulnerability where an attacker injects malicious scripts into a website, and the injected code gets reflected back to the user's browser, executing the script in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/photoblocks-grid-gallery-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/photoblocks-grid-gallery\/admin\/partials\/photoblocks-edit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_seatreg_redirect {
    meta:
        attack_type = "vuln_seatreg_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin SeatReg - Open Redirect: WordPress SeatReg plugin version 1.23.0 suffers from an open redirection vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/seatreg-redirect.yaml"
    strings:
        $param0 = /(^|[?&;])page=seatreg-welcome(&|$)/ nocase
        $param1 = /(^|[?&;])action=seatreg_create_submit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_seo_redirection_xss {
    meta:
        attack_type = "vuln_seo_redirection_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress SEO Redirection <7.4 - Cross-Site Scripting: WordPress SEO Redirection 7.4 does not escape the tab parameter before outputting it back in JavaScript code, leading to a reflected cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/seo-redirection-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=seo-redirection\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_shortcode_lfi {
    meta:
        attack_type = "vuln_shortcode_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Download Shortcode 0.2.3 - Local File Inclusion: WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/shortcode-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/force-download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_shortpixel_image_optimizer_xss {
    meta:
        attack_type = "vuln_shortpixel_image_optimizer_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress ShortPixel Image Optimizer <4.22.10 - Cross-Site Scripting: WordPress ShortPixel Image Optimizer 4.22.10 does not escape generated URLs before outputting them back in an attribute, leading to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/shortpixel-image-optimizer-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wp-shortpixel-settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_simple_file_list_rce {
    meta:
        attack_type = "vuln_simple_file_list_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Simple File List <=4.2.2 - Remote Code Execution: An unrestricted file upload vulnerability in the WordPress Simple File List plugin before version 4.2.3 allows unauthenticated remote attackers to achieve remote code execution. The plugin's upload endpoint."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/simple-file-list-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-content\/plugins\/simple-file-list\/ee-upload-engine\.php(\/|;|$)/ nocase
        $path1 = /\/wp-content\/plugins\/simple-file-list\/ee-file-engine\.php(\/|;|$)/ nocase
        $path2 = "/wp-content/uploads/simple-file-list/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_vrview_xss {
    meta:
        attack_type = "vuln_vrview_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VRview Plugin - Cross-Site Scripting: The VRview plugin is a tool commonly used to embed and display 360-degree virtual reality content in web applications. However, improper input sanitization in the plugin allows attackers to inject malicious scripts into trusted websites.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/vrview-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/vrview/vrview/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_w3c_total_cache_ssrf {
    meta:
        attack_type = "vuln_w3c_total_cache_ssrf"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wordpress W3C Total Cache <= 0.9.4 - Server Side Request Forgery (SSRF): The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/w3c-total-cache-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-content\/plugins\/w3-total-cache\/pub\/minify\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA\.css(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_watu_xss {
    meta:
        attack_type = "vuln_watu_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Watu Quiz < 3.1.2.6 - Cross Site Scripting: The Watu Quiz WordPress plugin was affected by a Reflected XSS via question-form.html.php security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/watu-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=watu_question(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_weekender_newspaper_open_redirect {
    meta:
        attack_type = "vuln_weekender_newspaper_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Weekender Newspaper 9.0 - Open Redirect: WordPress Weekender Newspaper theme 9.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/weekender-newspaper-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/weekender\/friend\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])id=aHR0cHM6Ly9pbnRlcmFjdC5zaA==(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_woocommerce_pdf_invoices_xss {
    meta:
        attack_type = "vuln_woocommerce_pdf_invoices_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WooCommerce PDF Invoices & Packing Slips <2.15.0 - Cross-Site Scripting: WordPress WooCommerce PDF Invoices & Packing Slips 2.15.0 does not escape some URLs before outputting them in attributes, leading to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/woocommerce-pdf-invoices-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])tab=documents(&|$)/ nocase
        $param1 = /(^|[?&;])section=invoice(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wordpress_affiliatewp_log {
    meta:
        attack_type = "vuln_wordpress_affiliatewp_log"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Plugin 'AffiliateWP -- Allowed Products' Log Disclosure: Exposed debug log in AffiliateWP Wordpress Plugin"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-affiliatewp-log.yaml"
    strings:
        $path0 = /\/wp-content\/uploads\/affwp-debug\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_bbpress_plugin_listing {
    meta:
        attack_type = "vuln_wordpress_bbpress_plugin_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress bbPress Plugin Directory Listing: Searches for sensitive directories present in the bbpress wordpress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-bbpress-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/bbpress/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_db_repair {
    meta:
        attack_type = "vuln_wordpress_db_repair"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Wordpress DB Repair Exposed: Discover enabled Wordpress repair page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-db-repair.yaml"
    strings:
        $path0 = /\/wp-admin\/maint\/repair\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_debug_log {
    meta:
        attack_type = "vuln_wordpress_debug_log"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Debug Log - Exposure: Exposed Wordpress debug log."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-debug-log.yaml"
    strings:
        $path0 = /\/debug\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_elementor_plugin_listing {
    meta:
        attack_type = "vuln_wordpress_elementor_plugin_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Elementor Plugin Directory Listing: Searches for sensitive directories present in the elementor wordpress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-elementor-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/elementor/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_emergency_script {
    meta:
        attack_type = "vuln_wordpress_emergency_script"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Emergency Script: Exposed wordpress password reset emergency script."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-emergency-script.yaml"
    strings:
        $path0 = /\/emergency\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_gtranslate_plugin_listing {
    meta:
        attack_type = "vuln_wordpress_gtranslate_plugin_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress gtranslate Plugin Directory Listing: Searches for sensitive directories present in the gtranslate wordpress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-gtranslate-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/gtranslate/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_installer_log {
    meta:
        attack_type = "vuln_wordpress_installer_log"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Installer Log: This file is generated during the installation process of wordpress and is exposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-installer-log.yaml"
    strings:
        $path0 = /\/installer-log\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_redirection_plugin_listing {
    meta:
        attack_type = "vuln_wordpress_redirection_plugin_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Redirection Plugin Directory Listing: Searches for sensitive directories present in the redirection plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-redirection-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/redirection/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_social_metrics_tracker {
    meta:
        attack_type = "vuln_wordpress_social_metrics_tracker"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Social Metrics Tracker <= 1.6.8 - Unauthorised Data Export: The lack of proper authorisation when exporting data from the plugin could allow unauthenticated users to get information about the posts and page of the blog, including their author's username and email."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-social-metrics-tracker.yaml"
    strings:
        $param0 = /(^|[?&;])page=social-metrics-tracker-export(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wordpress_ssrf_oembed {
    meta:
        attack_type = "vuln_wordpress_ssrf_oembed"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wordpress Oembed Proxy - Server-side request forgery: The oEmbed feature in WordPress allows embedding content from external sources, and if it's not properly secured, it could be exploited for SSRF."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-ssrf-oembed.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-json\/oembed\/1\.0\/proxy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_tmm_db_migrate {
    meta:
        attack_type = "vuln_wordpress_tmm_db_migrate"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress ThemeMarkers DB Migration File"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-tmm-db-migrate.yaml"
    strings:
        $path0 = /\/wp-content\/uploads\/tmm_db_migrate\/tmm_db_migrate\.zip(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_total_upkeep_backup_download {
    meta:
        attack_type = "vuln_wordpress_total_upkeep_backup_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Total Upkeep Database and Files Backup Download: Exposed sensitive file in WordPress Total Upkeep wordpress plugin feature used."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-total-upkeep-backup-download.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/boldgrid-backup\/cron\/restore-info\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_updraftplus_pem_keys {
    meta:
        attack_type = "vuln_updraftplus_pem_keys"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "UpdraftPlus Plugin Pem Key: UpdraftPlus wordpress plugin private key leaked with directory listing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-updraftplus-pem-key.yaml"
    strings:
        $path0 = "/wp-content/plugins/updraftplus/includes/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_woocommerce_listing {
    meta:
        attack_type = "vuln_wordpress_woocommerce_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress WooCommerce - Directory Search: WordPress WooCommerce plugin sensitive directory searches were conducted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-woocommerce-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/woocommerce/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_wordfence_lfi {
    meta:
        attack_type = "vuln_wordpress_wordfence_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Wordfence 7.4.5 - Local File Inclusion: WordPress Wordfence 7.4.5 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-wordfence-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wordfence\/lib\/wordfenceClass\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_wordfence_xss {
    meta:
        attack_type = "vuln_wordpress_wordfence_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Wordfence 7.4.6 - Cross0Site Scripting: WordPress Wordfence 7.4.6 is vulnerable to cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-wordfence-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/wordfence\/lib\/diffResult\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_zebra_form_xss {
    meta:
        attack_type = "vuln_wordpress_zebra_form_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zebra_Form PHP Library <= 2.9.8 - Cross-Site Scripting: Zebra_Form PHP library 2.9.8 and prior (which is used by some WordPress plugins) is affected by reflected cross-site scripting vulnerabilities via process.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wordpress-zebra-form-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-ticket\/assets\/ext\/zebraform\/process\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])control=upload(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_123contactform_plugin_listing {
    meta:
        attack_type = "vuln_wp_123contactform_plugin_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress 123ContactForm Plugin Directory Listing: Searches for sensitive directories present in the 123contactform-for-wordpress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-123contactform-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/123contactform-for-wordpress/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_adivaha_xss {
    meta:
        attack_type = "vuln_wp_adivaha_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Adivaha Travel Plugin 2.3 - Cross-Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-adivaha-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = "/mobile-app/v3/" ascii nocase
        $param0 = /(^|[?&;])pid=77A89299(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_altair_listing {
    meta:
        attack_type = "vuln_wp_altair_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Altair WordPress theme v4.8 - Directory Listing: Searches for directories listing in the altair theme."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-altair-listing.yaml"
    strings:
        $path0 = "/wp-content/themes/altair/modules/" ascii nocase
        $path1 = "/wp-content/themes/altair/functions/" ascii nocase
        $path2 = "/wp-content/themes/altair/images/flip/" ascii nocase
        $path3 = "/wp-content/themes/altair/images/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_ambience_xss {
    meta:
        attack_type = "vuln_wp_ambience_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Ambience Theme <=1.0 - Cross-Site Scripting: WordPress Ambience Theme 1.0 and earlier was affected by a cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-ambience-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/themes\/ambience\/thumb\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_arforms_listing {
    meta:
        attack_type = "vuln_wp_arforms_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Arforms Listing: Searches for sensitive directories present in the arforms plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-arforms-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/arforms/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_blogroll_fun_xss {
    meta:
        attack_type = "vuln_wp_blogroll_fun_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting: WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0.8.4 and possibly prior versions are prone to a cross-site scripting vulnerability because of a failure to properly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-blogroll-fun-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/blogroll-fun\/blogroll\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_buddypress_open_redirect {
    meta:
        attack_type = "vuln_wp_buddypress_open_redirect"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress BuddyPress < 2.9.2 - Authenticated Open Redirect: WordPress BuddyPress plugin before 2.9.2 contains an authenticated open redirect vulnerability via the wp_http_referer parameter on the bp-profile-edit admin page. After updating profile, the Back to Users link."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-buddypress-open-redirect.yaml"
    strings:
        $param0 = /(^|[?&;])page=bp-profile-edit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_caldera_forms_xss {
    meta:
        attack_type = "vuln_wp_caldera_forms_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Caldera Forms <= 1.5.4 - Cross-Site Scripting: The Caldera Forms WordPress plugin before 1.5.4 is affected by an cross-site scripting (XSS) vulnerability. Due to insufficient input sanitization and output escaping, attackers can inject arbitrary JavaScript via form submissions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-caldera-forms-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=caldera-forms(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_custom_tables_xss {
    meta:
        attack_type = "vuln_wp_custom_tables_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Custom Tables 3.4.4 - Cross-Site Scripting: WordPress Custom Tables 3.4.4 plugin contains a cross-site scripting vulnerability via the key parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-custom-tables-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/custom-tables\/iframe\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_ellipsis_xss {
    meta:
        attack_type = "vuln_wp_ellipsis_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ellipsis Human Presence Technology <= 2.0.8 - Cross Site Scripting: The 'page' GET parameter of the inc/protected-forms-table.php file was affected by a reflected XSS vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-ellipsis-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/ellipsis-human-presence-technology\/inc\/protected-forms-table\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_email_subscribers_listing {
    meta:
        attack_type = "vuln_wp_email_subscribers_listing"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Plugin Email Subscribers Listing: Searches for sensitive directories present in the email-subscribers plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-email-subscribers-listing.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/email-subscribers(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_finder_xss {
    meta:
        attack_type = "vuln_wp_finder_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Finder - Cross-Site Scripting: WordPress Plugin Finder contains a cross-site scripting vulnerability via the order parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-finder-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/finder\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_flagem_xss {
    meta:
        attack_type = "vuln_wp_flagem_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress FlagEm - Cross-Site Scripting: WordPress FlagEm plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-flagem-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/FlagEm\/flagit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_full_path_disclosure {
    meta:
        attack_type = "vuln_wp_full_path_disclosure"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "Wordpress - Path Disclosure: Wordpress internal file system path of a WordPress installation is exposed or disclosed to unauthorized users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-full-path-disclosure.yaml"
    strings:
        $path0 = /\/wp-includes\/rss-functions\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_gallery_file_upload {
    meta:
        attack_type = "vuln_wp_gallery_file_upload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Plugin Gallery 3.06 - Arbitrary File Upload: The Gallery by BestWebSoft WordPress plugin was affected by an Unauthenticated File Upload PHP Code Execution security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-gallery-file-upload.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/gallery-plugin\/upload\/php\.php(\/|;|$)/ nocase
        $path1 = "/wp-content/plugins/gallery-plugin/upload/files/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_googlemp3_lfi {
    meta:
        attack_type = "vuln_wp_googlemp3_lfi"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Plugin CodeArt Google MP3 Player - File Disclosure Download: WordPress Plugin CodeArt Google MP3 Player allows an unauthenticated attacker to download file from server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-googlemp3-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/google-mp3-audio-player\/direct_download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_grimag_open_redirect {
    meta:
        attack_type = "vuln_wp_grimag_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Grimag <1.1.1 - Open Redirection: WordPress Grimag theme before 1.1.1 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-grimag-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/Grimag\/go\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_gtranslate_open_redirect {
    meta:
        attack_type = "vuln_wp_gtranslate_open_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GTranslate < 2.8.11 - Open Redirect: The Translate WordPress with GTranslate WordPress plugin was affected by an Unauthenticated Open Redirect security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-gtranslate-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/gtranslate\/url_addon\/gtranslate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_haberadam_idor {
    meta:
        attack_type = "vuln_wp_haberadam_idor"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Themes Haberadam JSON API - IDOR and Path Disclosure: This template is designed to detect a misconfiguration vulnerability in WordPress themes that use the Haberadam JSON API. This vulnerability can lead to an Insecure Direct Object Reference (IDOR) and path."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-haberadam-idor.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/haberadam\/api\/mobile-info\.php(\/|;|$)/ nocase
        $path1 = /\/blog\/wp-content\/themes\/haberadam\/api\/mobile-info\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_idx_broker_platinum_listing {
    meta:
        attack_type = "vuln_wp_idx_broker_platinum_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Idx Broker Platinum Listing: Searches for sensitive directories present in the idx-broker-platinum plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-idx-broker-platinum-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/idx-broker-platinum/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_insert_php_xss {
    meta:
        attack_type = "vuln_wp_insert_php_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Woody Code Snippets <2.4.6 - Cross-Site Scripting: WordPress Woody Code Snippets plugin before 2.4.6 contains a cross-site scripting vulnerability. It does not escape generated URLs before outputting them back in an attribute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-insert-php-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=wbcr-snippets(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_iwp_client_listing {
    meta:
        attack_type = "vuln_wp_iwp_client_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Iwp-client Listing: Searches for sensitive directories present in the iwp-client plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-iwp-client-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/iwp-client/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_jetpack_ssrf {
    meta:
        attack_type = "vuln_wp_jetpack_ssrf"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wordpress Jetpack plugin - Server Side Request Forgery: The Jetpack WordPress plugin exposes an endpoint that fetches external URLs provided via the 'urls' parameter to retrieve Twitter (X) card descriptions/metadata. This allows unauthenticated SSRF, enabling attackers to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-jetpack-ssrf.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-json\/wpcom\/v2\/tweetstorm\/generate-cards(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_knews_xss {
    meta:
        attack_type = "vuln_wp_knews_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Knews Multilingual Newsletters 1.1.0 - Cross-Site Scripting: WordPress Knews Multilingual Newsletters 1.1.0 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-knews-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/knews/wysiwyg/fontpicker/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_mailchimp_log_exposure {
    meta:
        attack_type = "vuln_wp_mailchimp_log_exposure"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress MC4WP - Debug Log Exposure: Detected WordPress Mailchimp for WordPress (MC4WP) debug log. The log file may contain email addresses, Mailchimp API keys, and error details."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-mailchimp-log-exposure.yaml"
    strings:
        $path0 = /\/wp-content\/uploads\/mc4wp-debug\.log(\/|;|$)/ nocase
        $path1 = /\/wp-content\/uploads\/mc4wp-debug-log\.php(\/|;|$)/ nocase
        $path2 = /\/wp-content\/uploads\/mailchimp-for-wp\/debug-log\.php(\/|;|$)/ nocase
        $path3 = /\/wp-content\/uploads\/sites\/1\/mc4wp-debug-log\.php(\/|;|$)/ nocase
        $path4 = /\/wp-content\/uploads\/sites\/1\/mailchimp-for-wp\/debug-log\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_memphis_documents_library_lfi {
    meta:
        attack_type = "vuln_wp_memphis_documents_library_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Memphis Document Library 3.1.5 - Local File Inclusion: WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-memphis-documents-library-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])mdocs-img-preview=\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_mstore_plugin_listing {
    meta:
        attack_type = "vuln_wp_mstore_plugin_listing"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Wordpress Plugin MStore API: Searches for sensitive directories present in the mstore-api plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-mstore-plugin-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/mstore-api/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_nextgen_xss {
    meta:
        attack_type = "vuln_wp_nextgen_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress NextGEN Gallery 1.9.10 - Cross-Site Scripting: WordPress NextGEN Gallery 1.9.10 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-nextgen-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/nextgen-gallery\/nggallery\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_ninja_tables_lfi {
    meta:
        attack_type = "vuln_wp_ninja_tables_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ninja Tables <4.1.9 - Unauthenticated Arbitrary File Read: The Ninja Tables plugin for WordPress (versions < 4.1.9) is vulnerable to an unauthenticated arbitrary file download vulnerability. The issue exists due to the improper validation of the 'url' parameter in the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-ninja-tables-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])url=\/etc\/os-release(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_oxygen_theme_lfi {
    meta:
        attack_type = "vuln_wp_oxygen_theme_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Oxygen-Theme - Local File Inclusion: WordPress Oxygen-Theme has a local file inclusion vulnerability via the 'file' parameter of 'download.php'."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-oxygen-theme-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/themes\/oxygen-theme\/download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_phpfreechat_xss {
    meta:
        attack_type = "vuln_wp_phpfreechat_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress PHPFreeChat 0.2.8 - Cross-Site Scripting: WordPress PHPFreeChat 0.2.8 plugin contains a cross-site scripting vulnerability via the url parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-phpfreechat-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/phpfreechat\/lib\/csstidy-1\.2\/css_optimiser\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_plugin_1_flashgallery_listing {
    meta:
        attack_type = "vuln_wp_plugin_1_flashgallery_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress 1 flash gallery listing: Searches for sensitive directories present in the 1-flash-gallery plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-plugin-1-flashgallery-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/1-flash-gallery/" ascii nocase
        $path1 = "/blog/wp-content/plugins/1-flash-gallery/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_plugins_lifterlms {
    meta:
        attack_type = "vuln_wordpress_plugins_lifterlms"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin lifterlms Listing: Searches for sensitive directories present in the lifterlms plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-plugin-lifterlms.yaml"
    strings:
        $path0 = "/wp-content/plugins/lifterlms/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_plugins_ultimate_member {
    meta:
        attack_type = "vuln_wordpress_plugins_ultimate_member"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Ultimate Member: Searches for sensitive directories present in the ultimate-member plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-plugin-utlimate-member.yaml"
    strings:
        $path0 = "/wp-content/plugins/ultimate-member/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wordpress_popup_listing {
    meta:
        attack_type = "vuln_wordpress_popup_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Popup Plugin Directory Listing: Searches for sensitive directories present in the wordpress-popup plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-popup-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/wordpress-popup/views/admin/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_portrait_archiv_xss {
    meta:
        attack_type = "vuln_wp_portrait_archiv_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Portrait-Archiv.com Photostore 5.0.4 - Reflected Cross Site Scripting: The 'pDetails' GET parameter from the js/imageDetails.php was vulnerable to an unauthenticated reflected XSS attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-portrait-archiv-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/portrait-archiv-shop\/js\/imageDetails\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_prostore_open_redirect {
    meta:
        attack_type = "vuln_wp_prostore_open_redirect"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress ProStore <1.1.3 - Open Redirect: WordPress ProStore theme before 1.1.3 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-prostore-open-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/prostore\/go\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_qards_listing {
    meta:
        attack_type = "vuln_wp_qards_listing"
        classification = "attack"
        severity = 2
        confidence = "medium"
        description = "WordPress Plugin Qards: Searches for sensitive directories present in the qards plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-qards-listing.yaml"
    strings:
        $path0 = "/wp-content/plugins/qards/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_qwiz_online_xss {
    meta:
        attack_type = "vuln_wp_qwiz_online_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Qwiz Online Quizzes And Flashcards <= 3.36 - Cross-Site Scripting: The qname, i_qwiz, session_id and username parameters passed to the registration_complete.php file are affected by XSS issues."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-qwiz-online-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/qwiz-online-quizzes-and-flashcards\/registration_complete\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_related_post_xss {
    meta:
        attack_type = "vuln_wp_related_post_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Related Posts <= 2.1.1 - Cross Site Scripting: WordPress Related Posts plugin before 2.1.1 contains an Reflected XSS via rp4wp_parent"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-related-post-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=rp4wp_link_related(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_simple_fields_lfi {
    meta:
        attack_type = "vuln_wp_simple_fields_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Simple Fields 0.2 - 0.3.5 LFI/RFI/RCE: WordPress Simple Fields 0.2 is vulnerable to local file inclusion, remote file inclusion, and remote code execution."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-simple-fields-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/simple-fields\/simple_fields\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_slideshow_xss {
    meta:
        attack_type = "vuln_wp_slideshow_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Slideshow - Cross-Site Scripting: WordPress Slideshow plugin contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-slideshow-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/slideshow-jquery-image-gallery\/views\/SlideshowPlugin\/slideshow\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_smart_manager_sqli {
    meta:
        attack_type = "vuln_wp_smart_manager_sqli"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Smart Manager for WooCommerce & WPeC <= 3.9.6 - SQL Injection: The Smart Manager For WooCommerce Stock Management, Bulk Edit & more WordPress plugin was affected by an Unauthenticated SQL Injection security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-smart-manager-sqli.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])cmd=saveData(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_social_warfare_rce {
    meta:
        attack_type = "vuln_wp_social_warfare_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Social Warfare <= 3.5.2 - Remote Code Execution: Unauthenticated remote code execution has been discovered in functionality that handles settings import."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-social-warfare-rce.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])swp_debug=load_options(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_socialfit_xss {
    meta:
        attack_type = "vuln_wp_socialfit_xss"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress SocialFit - Cross-Site Scripting: WordPress SocialFit is vulnerable to a cross-site scripting vulnerability via the 'msg' parameter because it fails to properly sanitize user-supplied input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-socialfit-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/socialfit\/popup\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])service=googleplus(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wordpress_super_forms {
    meta:
        attack_type = "vuln_wordpress_super_forms"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress super-forms Plugin Directory Listing: Searches for sensitive directories present in the super-forms plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-super-forms.yaml"
    strings:
        $path0 = "/wp-content/plugins/super-forms/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_superstorefinder_misconfig {
    meta:
        attack_type = "vuln_wp_superstorefinder_misconfig"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Superstorefinder WP-plugin - Security Misconfigurations: Security misconfiguration is a common security issue that occurs when a system, application, or network is not properly configured to protect against threats and vulnerabilities."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-superstorefinder-misconfig.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/superstorefinder-wp\/ssf-wp-admin\/pages\/exportAjax\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_sym404 {
    meta:
        attack_type = "vuln_wp_sym404"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Wordpress sym404 directory: Searches for sensitive directories present in the sym404."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-sym404.yaml"
    strings:
        $path0 = /\/wp-includes\/sym404\/root\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_tinymce_lfi {
    meta:
        attack_type = "vuln_wp_tinymce_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tinymce Thumbnail Gallery <=1.0.7 - Local File Inclusion: Tinymce Thumbnail Gallery 1.0.7 and before are vulnerable to local file inclusion via download-image.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-tinymce-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/tinymce-thumbnail-gallery\/php\/download-image\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_tutor_lfi {
    meta:
        attack_type = "vuln_wp_tutor_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress tutor 1.5.3 - Local File Inclusion: WordPress tutor.1.5.3 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-tutor-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/tutor\/views\/pages\/instructors\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sub_page=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_upward_theme_redirect {
    meta:
        attack_type = "vuln_wp_upward_theme_redirect"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Upward Themes <1.5 - Open Redirect: WordPress Upward Themes 1.5 accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks. An http parameter may contain a URL value and could cause the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-upward-theme-redirect.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/Upward\/go\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wp_user_enum {
    meta:
        attack_type = "vuln_wp_user_enum"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress REST API User Enumeration: The REST API exposed user data for all users who had authored a post of a public post type. WordPress 4.7.1 limits this to only post types which have specified that they should be shown within the REST API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-user-enum.yaml"
    strings:
        $param0 = /(^|[?&;])rest_route=\/wp\/v2\/users\/(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_vault_local_file_inclusion {
    meta:
        attack_type = "vuln_wp_vault_local_file_inclusion"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Vault 0.8.6.6 - Local File Inclusion: WordPress Vault 0.8.6.6 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-vault-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])wpv-image=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_woocommerce_email_verification {
    meta:
        attack_type = "vuln_wp_woocommerce_email_verification"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass: Email Verification for WooCommerce Wordpress plugin prior to version 1.8.2 contains a loose comparison issue which could allow any user to log in as administrator."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-woocommerce-email-verification.yaml"
    strings:
        $param0 = /(^|[?&;])alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_woocommerce_file_download {
    meta:
        attack_type = "vuln_wp_woocommerce_file_download"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Product Input Fields for WooCommerce < 1.2.7 - Unauthenticated File Download: WordPress WooCommerce < 1.2.7 is susceptible to file download vulnerabilities. The lack of authorization checks in the handle_downloads() function hooked to admin_init() could allow unauthenticated."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-woocommerce-file-download.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])alg_wc_pif_download_file=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wp_woocommerce_pdf_invoice_listing {
    meta:
        attack_type = "vuln_wp_woocommerce_pdf_invoice_listing"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Woocommerce - PDF Invoice Exposure: A vulnerability in Woocommerce allows remote unauthenticated attackers to access company invoices and other sensitive information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wp-woocommerce-pdf-invoice-listing.yaml"
    strings:
        $path0 = "/wp-content/uploads/pdf-invoices/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wpdm_cache_session {
    meta:
        attack_type = "vuln_wpdm_cache_session"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wpdm-Cache Session: Leaked session of Wpdm Cache wordpress plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wpdm-cache-session.yaml"
    strings:
        $path0 = "/wp-content/uploads/wpdm-cache/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wpml_xss {
    meta:
        attack_type = "vuln_wpml_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting: WordPress Plugin WPML Version < 4.6.1 is vulnerable to RXSS via wp_lang parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wpml-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])wp_lang=en_US'(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_wpmudev_pub_keys {
    meta:
        attack_type = "vuln_wpmudev_pub_keys"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wpmudev Dashboard Pub Key: Wpmudev Wordpress Plugin public key leaked."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wpmudev-pub-keys.yaml"
    strings:
        $path0 = "/wp-content/plugins/wpmudev-updates/keys/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_wptouch_xss {
    meta:
        attack_type = "vuln_wptouch_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPtouch <4.3.44 - Cross-Site Scripting: WordPress WPtouch plugin prior to 4.3.44 contains a cross-site scripting vulnerability. The plugin does not escape some URLs before outputting them back in attributes. An attacker can inject arbitrary script in the browser of an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wordpress/wptouch-xss.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wptouch-admin-license(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_functions_php_disclosure {
    meta:
        attack_type = "vuln_functions_php_disclosure"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "functions.php Full Path Disclosure: Detected a full server file path disclosure in the WordPress functions.php file. This exposure revealed sensitive directory information that could have aided attackers in further exploitation."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/wp-functions-php-disclosure.yaml"
    strings:
        $path0 = /\/wp-content\/themes\/twentytwentyfour\/functions\.php(\/|;|$)/ nocase
        $path1 = /\/wp-content\/themes\/twentytwentythree\/functions\.php(\/|;|$)/ nocase
        $path2 = /\/wp-content\/themes\/twentytwentytwo\/functions\.php(\/|;|$)/ nocase
        $path3 = /\/wp-content\/themes\/twentytwentyone\/functions\.php(\/|;|$)/ nocase
        $path4 = /\/wp-content\/themes\/twentytwenty\/functions\.php(\/|;|$)/ nocase
        $path5 = /\/wp-content\/themes\/twentynineteen\/functions\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_gnremote_sqli {
    meta:
        attack_type = "vuln_chanjet_gnremote_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Changjietong Remote Communication GNRemote.dll - SQL Injection: Chanjetong has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/chanjet-gnremote-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/GNRemote\.dll(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_tplus_checkmutex_sqli {
    meta:
        attack_type = "vuln_chanjet_tplus_checkmutex_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chanjet Tplus CheckMutex - SQL Injection: There is an SQL injection vulnerability in the Changjetcrm financial crm system under Yonyou."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/chanjet-tplus-checkmutex-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/tplus\/ajaxpro\/Ufida\.T\.SM\.UIP\.MultiCompanyController,Ufida\.T\.SM\.UIP\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=CheckMutex(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_chanjet_tplus_file_read {
    meta:
        attack_type = "vuln_chanjet_tplus_file_read"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chanjet TPlus DownloadProxy.aspx - Arbitrary File Read: Chanjet TPlus DownloadProxy.aspx file has an arbitrary file reading vulnerability. An attacker can obtain sensitive files on the server through the vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/chanjet-tplus-file-read.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/tplus\/SM\/DTS\/DownloadProxy\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_tplus_fileupload {
    meta:
        attack_type = "vuln_chanjet_tplus_fileupload"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "UFIDA Chanjet TPluse Upload.aspx - Arbitrary File Upload: There is an arbitrary file upload vulnerability in the Upload.aspx interface of UFIDA Chanjet TPlus. An attacker can use the preload parameter to bypass authentication to upload files and control the server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/chanjet-tplus-fileupload.yaml"
    strings:
        $path0 = /\/tplus\/SM\/SetupAccount\/Upload\.aspx(\/|;|$)/ nocase
        $path1 = "/tplus/img/login/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_chanjet_tplus_ufida_sqli {
    meta:
        attack_type = "vuln_chanjet_tplus_ufida_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Chanjet TPluse Ufida.T.SM.Login.UIP - SQL injection: Chanjet TPluse application has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/chanjet-tplus-ufida-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/tplus\/ajaxpro\/Ufida\.T\.SM\.Login\.UIP\.LoginManager,Ufida\.T\.SM\.Login\.UIP\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=CheckPassword(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_grp_u8_uploadfiledata {
    meta:
        attack_type = "vuln_grp_u8_uploadfiledata"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UFIDA GRP-U8 UploadFileData - Arbitrary File Upload: File upload vulnerability in UFIDA U8+ERP customer relationship management software. An attacker can use this vulnerability to gain control of the server."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/grp-u8-uploadfiledata-fileupload.yaml"
    strings:
        $path0 = /\/UploadFileData(\/|;|$)/ nocase
        $path1 = "/R9iPortal/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_fe_directory_traversal {
    meta:
        attack_type = "vuln_yonyou_fe_directory_traversal"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FE collaborative Office templateOfTaohong_manager.jsp - Path Traversal: There is a directory traversal vulnerability in the templateOfTaohong_manager.jsp file of UFIDA FE collaborative office platform. Through the vulnerability, attackers can obtain directory files and other."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-fe-directory-traversal.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/system\/mediafile\/templateOfTaohong_manager\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_filereceiveservlet_fileupload {
    meta:
        attack_type = "vuln_yonyou_filereceiveservlet_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yonyou NC FileReceiveServlet - Aribitrary File Upload: An unauthorized attacker can upload a file via the FileReceiveServlet endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-filereceiveservlet-fileupload.yaml"
    strings:
        $path0 = /\/servlet\/FileReceiveServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_accept_fileupload {
    meta:
        attack_type = "vuln_yonyou_nc_accept_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "YonYou NC Accept Upload - Arbitray File Upload: Arbitrary file upload vulnerability in UFIDA N C accept.jsp . An attacker can obtain website permissions through the vulnerability."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-accept-fileupload.yaml"
    strings:
        $path0 = /\/aim\/equipmap\/accept\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_baseapp_deserialization {
    meta:
        attack_type = "vuln_yonyou_nc_baseapp_deserialization"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Yonyou NC BaseApp UploadServlet - Deserialization Detect: Yonyou NC is an enterprise-level management software, widely used in large and medium-sized enterprises.Realize modeling, development, inheritance, operation, management integration of IT solution information."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-baseapp-deserialization.yaml"
    strings:
        $path0 = /\/service\/~baseapp\/UploadServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_dispatcher_fileupload {
    meta:
        attack_type = "vuln_yonyou_nc_dispatcher_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yonyou NC ServiceDispatcher Servlet - Arbitrary File Upload: Yonyou NC ServiceDispatcherServlet deserialization file upload vulnerability."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-dispatcher-fileupload.yaml"
    strings:
        $path0 = /\/ServiceDispatcherServlet(\/|;|$)/ nocase
        $path1 = /\/ncupload\/n2d19a\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_grouptemplet_fileupload {
    meta:
        attack_type = "vuln_yonyou_nc_grouptemplet_fileupload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UFIDA NC Grouptemplet Interface - Unauthenticated File Upload: The UFIDA NC Grouptemplet Interface permits unauthenticated users to upload potentially malicious files."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-grouptemplet-fileupload.yaml"
    strings:
        $path0 = /\/uapim\/upload\/grouptemplet(\/|;|$)/ nocase
        $path1 = "/uapim/static/pages/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_info_leak {
    meta:
        attack_type = "vuln_yonyou_nc_info_leak"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Yonyou UFIDA NC - Information Exposure: After logging in and visiting the address where the information was leaked, you will have permission to upload files. Then just go back to the homepage and view the published content directly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-info-leak.yaml"
    strings:
        $path0 = /\/service\/~iufo\/com\.ufida\.web\.action\.ActionServlet(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=nc\.ui\.iufo\.release\.InfoReleaseAction(&|$)/ nocase
        $param1 = /(^|[?&;])method=createBBSRelease(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_yonyou_nc_lfi {
    meta:
        attack_type = "vuln_yonyou_nc_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "UFIDA NC - Arbitrary File Read: UFIDA NC is vulnerable to an arbitrary file read vulnerability in the nc.uap.lfw.file.action.DocServlet component. An unauthenticated remote attacker can exploit this flaw to read sensitive files on the server by sending crafted requests."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/service\/~webrt\/nc\.uap\.lfw\.file\.action\.DocServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_nc_ncmessageservlet_rce {
    meta:
        attack_type = "vuln_yonyou_nc_ncmessageservlet_rce"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UFIDA NC NCMessageServlet - Deserialization RCE Detection: UFIDA NC is in the process of processing client request data. Insufficient checking and filtering when deserializing user-supplied data can lead to malicious deserialization operations and execution of commands on the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-nc-ncmessageservlet-rce.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/servlet\/~baseapp\/nc\.message\.bs\.NCMessageServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_u8_crm_sqli {
    meta:
        attack_type = "vuln_yonyou_u8_crm_sqli"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "UFIDA U8 CRM cfillbacksetting.php - SQL Injection: UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-u8-crm-sqli.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/config\/fillbacksettingedit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_u9_patchfile_upload {
    meta:
        attack_type = "vuln_yonyou_u9_patchfile_upload"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yonyou U9 PatchFile.asmx - Unauthenticated Arbitrary File Upload: An arbitrary file upload vulnerability in U9 PatchFile.asmx allows attackers to upload files to the server.This can lead to various security issues including remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-u9-patchfile-upload.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/CS\/Office\/AutoUpdates\/PatchFile\.asmx(\/|;|$)/ nocase
        $path1 = "/CS/Office/AutoUpdates/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_yonyou_ufida_nc_lfi {
    meta:
        attack_type = "vuln_yonyou_ufida_nc_lfi"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "UFIDA NC Portal - Arbitrary File Read: There is any file reading in the getFileLocal interface of UFIDA Mobile System Management."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/yonyou/yonyou-ufida-nc-lfi.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])cmd=getFileLocal(&|$)/ nocase
        $param1 = /(^|[?&;])fileid=\.\.\/\.\.\/\.\.\/\.\.\/webapps\/nc_web\/WEB-INF\/web\.xml(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_vuln_zend_v1_xss {
    meta:
        attack_type = "vuln_zend_v1_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ZendFramework 1.12.2 - Cross-Site Scripting: ZendFramework of versions <=1.12.2 contain a cross-site scripting vulnerability via an arbitrarily supplied parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/zend/zend-v1-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/vendor\/diablomedia\/zendframework1-http\/tests\/Zend\/Http\/Client\/_files\/testRedirections\.php(\/|;|$)/ nocase
        $path1 = /\/tests\/Zend\/Http\/Client\/_files\/testRedirections\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_unauth_ztp_ping {
    meta:
        attack_type = "vuln_unauth_ztp_ping"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Unauthenticated ZyXEL USG ZTP - Detect: Make a ZyXEL USG with ZTP support, pre CVE-2023-28771 patch, do a DNS lookup by asking it to make an ICMP request. This template can be used to detect hosts potentially vulnerable to CVE-2023-28771, CVE-2022-30525, and other issues."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/zyxel/unauth-ztp-ping.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ztp\/cgi-bin\/handler(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zzzcms_info_disclosure {
    meta:
        attack_type = "vuln_zzzcms_info_disclosure"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Zzzcms 1.75 - Information Disclosure: There is a rather strange file that directly echoes some content belonging to the inaccessible zzz_config.php. The information leakage file is located in plugins/webuploader/js/webconfig.php, and the management path name of the management."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/zzzcms/zzzcms-info-disclosure.yaml"
    strings:
        $path0 = /\/plugins\/webuploader\/js\/webconfig\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_vuln_zzzcms_xss {
    meta:
        attack_type = "vuln_zzzcms_xss"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zzzcms 1.75 - Cross-Site Scripting: ZzzCMS ( A Lightweight ASP.NET content management system ) is vulnerable to XSS( Cross-Site Scripting )."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        reference = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/zzzcms/zzzcms-xss.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugins\/template\/login\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])backurl=1 onmouseover=alert\(\/document\.domain\/\) y=(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
