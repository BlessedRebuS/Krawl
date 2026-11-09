// Exploit indicators for enterprise and edge products that internet scanners
// and botnets probe constantly. Each rule keys on the strongest single
// indicator (a vendor-specific path, parameter or header) because a rule
// cannot require a path AND a header; those rules use confidence = medium.
// Indicators follow the public vendor advisories and NVD entries cited in
// each rule's reference field. Fake attacks use RFC 5737 hosts only.

rule krawl_cve_2022_22965_spring4shell {
    meta:
        attack_type = "cve_2022_22965"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Spring4Shell: class.module.classLoader property binding used to reach Tomcat logging and write a webshell."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-22965"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
    strings:
        $a = /class\.(module\.)?classLoader\./ nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2022_22963_spring_cloud_function {
    meta:
        attack_type = "cve_2022_22963"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Spring Cloud Function SpEL injection through the routing-expression header or the functionRouter endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-22963"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22963"
    strings:
        $spel_type = "T(" ascii
        $spel_new = "new " ascii
        $spel_rt = "getRuntime" ascii nocase
        $router = "/functionRouter" ascii nocase
    condition:
        (scan_target == "header" and header_name == "spring.cloud.function.routing-expression" and any of ($spel*)) or (scan_target == "path" and $router)
}

rule krawl_cve_2022_22947_spring_cloud_gateway {
    meta:
        attack_type = "cve_2022_22947"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Spring Cloud Gateway actuator route injection, used to run SpEL expressions through /actuator/gateway/routes."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-22947"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22947"
        response_type = "spring_actuator"
    strings:
        $routes = "/actuator/gateway/routes" ascii nocase
        $refresh = "/actuator/gateway/refresh" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2017_5638_struts2_content_type {
    meta:
        attack_type = "cve_2017_5638"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Apache Struts 2 Jakarta multipart parser OGNL injection delivered in the Content-Type header."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2017-5638"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    strings:
        $a = "%{(#" ascii
        $b = "#_memberAccess" ascii
        $c = "ognl.OgnlContext" ascii nocase
    condition:
        scan_target == "header" and header_name == "content-type" and any of them
}

rule krawl_cve_2013_2251_struts2_redirect {
    meta:
        attack_type = "cve_2013_2251"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Apache Struts 2 DefaultActionMapper redirect:/redirectAction: prefix evaluated as an OGNL expression."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2013-2251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2251"
    strings:
        $r1 = "redirect:${" ascii nocase
        $r2 = "redirect:%{" ascii nocase
        $r3 = "redirectAction:${" ascii nocase
        $r4 = "redirectAction:%{" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2023_50164_struts2_upload_traversal {
    meta:
        attack_type = "cve_2023_50164"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Apache Struts 2 file upload parameter pollution (top.uploadFileName) used for path traversal and webshell upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-50164"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50164"
    strings:
        $a = "top.uploadFileName" ascii nocase
        $b = "top.uploadContentType" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2020_14882_weblogic_console {
    meta:
        attack_type = "cve_2020_14882"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Oracle WebLogic console authentication bypass by traversal into /console/css or /console/images, then ShellSession handle."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-14882, CVE-2020-14883"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14882, https://nvd.nist.gov/vuln/detail/CVE-2020-14883"
    strings:
        $trav = /\/console\/(css|images)\/(\.\.|%2e%2e|%252e%252e)/ ascii nocase
        $mvel = "com.tangosol.coherence.mvel2.sh.ShellSession" ascii
        $ctx = "FileSystemXmlApplicationContext" ascii
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2017_10271_weblogic_wls_wsat {
    meta:
        attack_type = "cve_2017_10271"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Oracle WebLogic WLS Security component deserialization through the wls-wsat endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2017-10271"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-10271"
    strings:
        $a = "/wls-wsat/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_2725_weblogic_async {
    meta:
        attack_type = "cve_2019_2725"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Oracle WebLogic _async AsyncResponseService deserialization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-2725"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $a = "/_async/AsyncResponseService" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_41773_apache_path_traversal {
    meta:
        attack_type = "cve_2021_41773"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Apache httpd 2.4.49/2.4.50 path traversal and RCE through encoded dot segments under /cgi-bin or /icons."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-41773, CVE-2021-42013"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-41773, https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
    strings:
        $cgi = /\/cgi-bin\/(\.|%2e){1,2}\// ascii nocase
        $icons = /\/icons\/(\.|%2e){1,2}\// ascii nocase
        $double = ".%%32%65" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2022_26134_confluence_ognl {
    meta:
        attack_type = "cve_2022_26134"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Confluence Server OGNL injection through an expression embedded in the URL path."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-26134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-26134"
    strings:
        $a = /\$\{[@(#][^}]{0,60}(java\.lang|Runtime|ProcessBuilder)/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2021_26084_confluence_ognl_vars {
    meta:
        attack_type = "cve_2021_26084"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Confluence Server OGNL injection through the page variable endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-26084"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26084"
    strings:
        $a = "/pages/doenterpagevariables.action" ascii nocase
        $b = "/pages/createpage-entervariables.action" ascii nocase
        $c = "/users/user-dark-features" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_22515_confluence_setup {
    meta:
        attack_type = "cve_2023_22515"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Confluence Data Center broken access control: re-opening the setup wizard to create an administrator."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-22515"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"
    strings:
        $a = "setupComplete=false" ascii nocase
        $b = "/setup/setupadministrator.action" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2023_22518_confluence_restore {
    meta:
        attack_type = "cve_2023_22518"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Confluence improper authorization on the setup-restore endpoints, allowing a database import."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-22518"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22518"
    strings:
        $a = /\/json\/setup-restore(-local|-progress)?\.action/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_22527_confluence_template {
    meta:
        attack_type = "cve_2023_22527"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Confluence template injection in the unauthenticated text-inline.vm Velocity template."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-22527"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22527"
    strings:
        $a = "/template/aui/text-inline.vm" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_11581_jira_contact_admin {
    meta:
        attack_type = "cve_2019_11581"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jira Server template injection through the ContactAdministrators form."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-11581"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11581"
    strings:
        $a = "/secure/ContactAdministrators!default.jspa" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_26855_exchange_proxylogon {
    meta:
        attack_type = "cve_2021_26855"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Exchange ProxyLogon SSRF through the X-BEResource / X-AnonResource-Backend cookie, or the ECP DDI SetObject file write."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-26855, CVE-2021-27065"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26855, https://nvd.nist.gov/vuln/detail/CVE-2021-27065"
    strings:
        $anon = "X-AnonResource-Backend=" ascii nocase
        $be = "X-BEResource=" ascii nocase
        $ddi = "/ecp/DDI/DDIService.svc/SetObject" ascii nocase
        $js = "/ecp/x.js" ascii nocase
    condition:
        (scan_target == "header" and header_name == "cookie" and ($anon or $be)) or (scan_target == "path" and ($ddi or $js))
}

rule krawl_cve_2021_34473_exchange_proxyshell {
    meta:
        attack_type = "cve_2021_34473"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Exchange ProxyShell autodiscover SSRF into the MAPI or PowerShell back-end endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-34473, CVE-2021-34523, CVE-2021-31207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-34473, https://nvd.nist.gov/vuln/detail/CVE-2021-34523, https://nvd.nist.gov/vuln/detail/CVE-2021-31207"
    strings:
        $nspi = "/mapi/nspi" ascii nocase
        $json = "autodiscover.json?@" ascii nocase
        $rps = "X-Rps-CAT=" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2022_41040_exchange_proxynotshell {
    meta:
        attack_type = "cve_2022_41040"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Exchange ProxyNotShell SSRF: autodiscover.json used as the Email value to reach the back end."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-41040"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41040"
    strings:
        $a = "Email=autodiscover/autodiscover.json" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2021_21972_vcenter_uploadova {
    meta:
        attack_type = "cve_2021_21972"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "VMware vCenter vROps plugin unauthenticated OVA upload leading to code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-21972"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21972"
    strings:
        $a = "/ui/vropspluginui/rest/services/uploadova" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_22005_vcenter_telemetry_upload {
    meta:
        attack_type = "cve_2021_22005"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "VMware vCenter analytics service arbitrary file upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-22005"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22005"
    strings:
        $a = "/analytics/telemetry/ph/api/hyper/send" ascii nocase
        $b = "/analytics/ceip/sdk/..;" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_21985_vcenter_vsan {
    meta:
        attack_type = "cve_2021_21985"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "VMware vCenter Virtual SAN Health Check plug-in remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-21985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21985"
    strings:
        $a = "vsanProviderUtils_setVmodlHelper" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2022_22954_workspace_one_ssti {
    meta:
        attack_type = "cve_2022_22954"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "VMware Workspace ONE Access server-side template injection through the catalog-portal verify endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-22954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22954"
    strings:
        $a = "freemarker.template.utility.Execute" ascii nocase
        $b = "deviceUdid=${" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2019_19781_citrix_adc_traversal {
    meta:
        attack_type = "cve_2019_19781"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Citrix ADC/Gateway directory traversal from /vpn/ into /vpns/portal/scripts, used to run Perl templates."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-19781"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19781"
    strings:
        $a = "/vpn/../vpns/" ascii nocase
        $b = "/vpns/portal/scripts/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_3519_citrix_adc_formssso {
    meta:
        attack_type = "cve_2023_3519"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix ADC/Gateway unauthenticated stack overflow reached through /gwtest/formssso."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-3519"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3519"
    strings:
        $a = "/gwtest/formssso" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_5902_f5_tmui {
    meta:
        attack_type = "cve_2020_5902"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "F5 BIG-IP Traffic Management UI authentication bypass with ..; traversal after login.jsp."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-5902, CVE-2023-46747"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902, https://nvd.nist.gov/vuln/detail/CVE-2023-46747"
    strings:
        $a = "/tmui/login.jsp/..;/" ascii nocase
        $b = "/tmui/locallb/workspace/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2022_1388_f5_icontrol_bash {
    meta:
        attack_type = "cve_2022_1388"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "F5 BIG-IP iControl REST authentication bypass reaching the bash utility endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-1388"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1388"
    strings:
        $a = "/mgmt/tm/util/bash" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_46805_ivanti_connect_secure {
    meta:
        attack_type = "cve_2023_46805"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Ivanti Connect Secure / Policy Secure authentication bypass chained with command injection in the licensing API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-46805, CVE-2024-21887"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-46805, https://nvd.nist.gov/vuln/detail/CVE-2024-21887"
    strings:
        $a = "/api/v1/totp/user-backup-code/" ascii nocase
        $b = "/api/v1/license/keys-status/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_35078_ivanti_epmm {
    meta:
        attack_type = "cve_2023_35078"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Ivanti Endpoint Manager Mobile (MobileIron Core) authentication bypass on /mifs API paths."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-35078, CVE-2023-35082"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35078, https://nvd.nist.gov/vuln/detail/CVE-2023-35082"
    strings:
        $a = "/mifs/aad/api/v2/" ascii nocase
        $b = "/mifs/asfv3/api/v2/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_11510_pulse_secure_dana {
    meta:
        attack_type = "cve_2019_11510"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Pulse Connect Secure pre-auth arbitrary file read through /dana-na/../dana/html5acc/guacamole."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-11510"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11510"
    strings:
        $a = "/dana-na/../dana/" ascii nocase
        $b = "/dana/html5acc/guacamole/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2018_13379_fortios_fgt_lang {
    meta:
        attack_type = "cve_2018_13379"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "FortiOS SSL VPN path traversal in /remote/fgt_lang to read the session file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2018-13379"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13379"
    strings:
        $a = "lang=/../" ascii nocase
        $b = "dev/cmdb/sslvpn_websession" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2022_40684_fortios_auth_bypass {
    meta:
        attack_type = "cve_2022_40684"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "FortiOS/FortiProxy administrative interface authentication bypass using the Report Runner user agent or a loopback Forwarded header."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-40684"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40684"
    strings:
        $ua = "Report Runner" ascii
        $fwd = "[127.0.0.1]:" ascii
        $api = "/api/v2/cmdb/system/admin" ascii nocase
    condition:
        (scan_target == "user_agent" and $ua) or (scan_target == "header" and header_name == "forwarded" and $fwd) or (scan_target == "path" and $api)
}

rule krawl_cve_2024_3400_panos_globalprotect {
    meta:
        attack_type = "cve_2024_3400"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "PAN-OS GlobalProtect SESSID cookie path traversal or command injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-3400"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
    strings:
        $trav = "SESSID=../" ascii nocase
        $ifs = "${IFS}" ascii
        $sub = /SESSID=[^;]{0,30}\$\(/ ascii
    condition:
        scan_target == "header" and header_name == "cookie" and any of them
}

rule krawl_cve_2023_20198_cisco_ios_xe_webui {
    meta:
        attack_type = "cve_2023_20198"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Cisco IOS XE web UI privilege escalation: logoutconfirm.html with logon_hash, or the webui_wsma service endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-20198"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"
    strings:
        $a = "/webui/logoutconfirm.html" ascii nocase
        $b = /webui_wsma_https?/ ascii nocase
        $c = "logon_hash=" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2020_3452_cisco_asa_cscot {
    meta:
        attack_type = "cve_2020_3452"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "Cisco ASA/FTD web services read-only path traversal through /+CSCOT+/translation-table."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-3452"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3452"
    strings:
        $a = "/+CSCOT+/translation-table" ascii nocase
        $b = "textdomain=/+CSCOE+/" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2019_1653_cisco_rv_config_exp {
    meta:
        attack_type = "cve_2019_1653"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco Small Business RV320/RV325 unauthenticated configuration download via /cgi-bin/config.exp."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-1653"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1653"
    strings:
        $a = "/cgi-bin/config.exp" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_34362_moveit_transfer {
    meta:
        attack_type = "cve_2023_34362"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "MOVEit Transfer SQL injection chain: X-siLock-* headers or the human2.aspx webshell."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-34362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"
    strings:
        $t1 = "folder_add_by_path" ascii nocase
        $t2 = "session_setvars" ascii nocase
        $h2 = "/human2.aspx" ascii nocase
    condition:
        (scan_target == "header" and header_name == "x-silock-transaction" and any of ($t*)) or (scan_target == "path" and $h2)
}

rule krawl_cve_2023_42793_teamcity_rpc2 {
    meta:
        attack_type = "cve_2023_42793"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "JetBrains TeamCity authentication bypass creating an administrator token through /app/rest/users/id:1/tokens."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-42793"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-42793"
    strings:
        $a = "/app/rest/users/id:1/tokens" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2024_27198_teamcity_jsp_bypass {
    meta:
        attack_type = "cve_2024_27198"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "JetBrains TeamCity authentication bypass using a ;.jsp suffix on REST endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-27198"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27198"
    strings:
        $a = "jsp=/app/rest/" ascii nocase
        $b = ";.jsp" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2018_1000861_jenkins_stapler {
    meta:
        attack_type = "cve_2018_1000861"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Jenkins Stapler routing flaw reaching the script-security checkScript endpoints without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2018-1000861"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000861"
    strings:
        $a = /\/descriptorByName\/org\.jenkinsci\.plugins\.[a-z0-9_.]{5,100}\/checkScript/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2024_23897_jenkins_cli_file_read {
    meta:
        attack_type = "cve_2024_23897"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jenkins CLI arbitrary file read through args4j @file expansion on the remoting=false endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-23897"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"
    strings:
        $a = "remoting=false" ascii nocase
    condition:
        scan_target == "query" and any of them
}

rule krawl_cve_2021_22205_gitlab_exiftool {
    meta:
        attack_type = "cve_2021_22205"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "GitLab ExifTool DjVu upload remote code execution; matches the DjVu AT&TFORM magic in an upload body."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate DjVu document uploads to a document-sharing site."
        cve = "CVE-2021-22205"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"
    strings:
        $a = "AT&TFORM" ascii
    condition:
        scan_target == "body" and any of them
}

rule krawl_cve_2023_7028_gitlab_password_reset {
    meta:
        attack_type = "cve_2023_7028"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "GitLab account takeover: password reset request carrying an array of email addresses."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-7028"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-7028"
    strings:
        $a = "user[email][]=" ascii nocase
    condition:
        (scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2023_38646_metabase_setup_token {
    meta:
        attack_type = "cve_2023_38646"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Metabase pre-auth RCE through /api/setup/validate with an H2 INIT script."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-38646"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38646"
    strings:
        $a = "/api/setup/validate" ascii nocase
        $b = "INIT=RUNSCRIPT" ascii nocase
        $c = "MODE=MSSQLServer;INIT=" ascii nocase
    condition:
        (scan_target == "path" and $a) or (scan_target == "body" and ($b or $c))
}

rule krawl_cve_2023_27350_papercut_setup {
    meta:
        attack_type = "cve_2023_27350"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "PaperCut NG/MF authentication bypass by calling the SetupCompleted page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-27350"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27350"
    strings:
        $a = "service=page/SetupCompleted" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2019_18935_telerik_ui {
    meta:
        attack_type = "cve_2019_18935"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Telerik UI for ASP.NET AJAX WebResource, DialogHandler or SpellCheck handlers, abused for deserialization and file upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-18935, CVE-2017-9248"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18935, https://nvd.nist.gov/vuln/detail/CVE-2017-9248"
    strings:
        $a = "Telerik.Web.UI.WebResource.axd" ascii nocase
        $b = "Telerik.Web.UI.DialogHandler.aspx" ascii nocase
        $c = "Telerik.Web.UI.SpellCheckHandler.axd" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_40539_manageengine_adselfservice {
    meta:
        attack_type = "cve_2021_40539"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Zoho ManageEngine ADSelfService Plus REST API authentication bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-40539"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40539"
    strings:
        $a = "/RestAPI/LogonCustomization" ascii nocase
        $b = "/RestAPI/Connection" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_10189_manageengine_desktop_central {
    meta:
        attack_type = "cve_2020_10189"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Zoho ManageEngine Desktop Central deserialization through the mdmLogUploader endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-10189"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10189"
    strings:
        $a = "/mdm/client/v1/mdmLogUploader" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2024_36401_geoserver_eval {
    meta:
        attack_type = "cve_2024_36401"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "GeoServer OGC request parameter property-name evaluation leading to code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-36401"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36401"
    strings:
        $a = "exec(java.lang.Runtime" ascii nocase
        $b = "javax.script.ScriptEngineManager" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2016_4437_shiro_rememberme {
    meta:
        attack_type = "cve_2016_4437"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Shiro rememberMe cookie carrying a long serialized payload (default-key deserialization)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate Shiro applications set rememberMe cookies, but they are short; a 300 character value is not expected."
        cve = "CVE-2016-4437"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4437"
    strings:
        $a = /rememberMe=[A-Za-z0-9+\/=]{300,}/ ascii
    condition:
        scan_target == "header" and header_name == "cookie" and $a
}

rule krawl_cve_2017_12615_tomcat_put_jsp {
    meta:
        attack_type = "cve_2017_12615"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Apache Tomcat PUT upload of a .jsp file using a trailing slash, space or ::$DATA to bypass the extension filter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2017-12615"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12615"
    strings:
        $a = /\.jsp(\/| |::\$data)$/ ascii nocase
    condition:
        http_method == "PUT" and scan_target == "path" and $a
}

rule krawl_cve_2023_51467_ofbiz_auth_bypass {
    meta:
        attack_type = "cve_2023_51467"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Apache OFBiz authentication bypass through requirePasswordChange=Y on webtools endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-51467, CVE-2023-49070"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-51467, https://nvd.nist.gov/vuln/detail/CVE-2023-49070"
    strings:
        $a = "requirePasswordChange=Y" ascii nocase
        $b = "/webtools/control/xmlrpc" ascii nocase
        $c = "/webtools/control/ProgramExport" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2021_29441_nacos_auth_bypass {
    meta:
        attack_type = "cve_2021_29441"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Alibaba Nacos authentication bypass using the Nacos-Server user agent against the auth API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-29441"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-29441"
    strings:
        $ua = "Nacos-Server" ascii
        $api = "/nacos/v1/auth/users" ascii nocase
    condition:
        (scan_target == "user_agent" and $ua) or (scan_target == "path" and $api)
}

rule krawl_cve_2022_36804_bitbucket_archive {
    meta:
        attack_type = "cve_2022_36804"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Atlassian Bitbucket Server command injection through the archive endpoint prefix parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-36804"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36804"
    strings:
        $a = "--exec=" ascii nocase
    condition:
        scan_target == "query" and any of them
}

rule krawl_cve_2022_27925_zimbra_mboximport {
    meta:
        attack_type = "cve_2022_27925"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Zimbra Collaboration mboximport arbitrary file upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-27925, CVE-2022-37042"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27925, https://nvd.nist.gov/vuln/detail/CVE-2022-37042"
    strings:
        $a = "/service/extension/backup/mboximport" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2022_21587_oracle_ebs_bne {
    meta:
        attack_type = "cve_2022_21587"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Oracle E-Business Suite BNE upload endpoints with bne:uueupload=TRUE."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2022-21587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-21587"
    strings:
        $a = "bne:uueupload=TRUE" ascii nocase
        $b = "/OA_HTML/BneViewerXMLService" ascii nocase
        $c = "/OA_HTML/BneUploaderService" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2020_6287_sap_netweaver_recon {
    meta:
        attack_type = "cve_2020_6287"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "SAP NetWeaver AS Java Visual Composer / LM Configuration Wizard unauthenticated access (RECON)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-6287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6287"
    strings:
        $a = "/CTCWebService/CTCWebServiceBean" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2025_31324_sap_metadata_uploader {
    meta:
        attack_type = "cve_2025_31324"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "SAP NetWeaver Visual Composer metadata uploader unauthenticated file upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2025-31324"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-31324"
    strings:
        $a = "/developmentserver/metadatauploader" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_15107_webmin_password_change {
    meta:
        attack_type = "cve_2019_15107"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Webmin password_change.cgi command injection through the old password field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-15107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15107"
    strings:
        $a = /old=(\||;|`|\$\()/ ascii
    condition:
        scan_target == "body" and any of them
}

rule krawl_cve_2023_32315_openfire_setup_traversal {
    meta:
        attack_type = "cve_2023_32315"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Openfire setup environment path traversal using %u002e dot encoding to reach admin pages."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-32315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-32315"
    strings:
        $a = "/setup/setup-s/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_43798_grafana_plugin_traversal {
    meta:
        attack_type = "cve_2021_43798"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "Grafana unauthenticated arbitrary file read through the /public/plugins/<id>/ path."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2021-43798"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-43798"
    strings:
        $a = /\/public\/plugins\/[a-z0-9-]{3,40}\/(\.\.|%2e%2e)/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_5418_rails_accept_traversal {
    meta:
        attack_type = "cve_2019_5418"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "Ruby on Rails Action View file disclosure through a path traversal in the Accept header."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-5418"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
    strings:
        $a = "../" ascii
    condition:
        scan_target == "header" and header_name == "accept" and $a
}

rule krawl_cve_2025_29927_nextjs_middleware_bypass {
    meta:
        attack_type = "cve_2025_29927"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Next.js middleware authorization bypass using the internal x-middleware-subrequest header."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2025-29927"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-29927"
    strings:
        $a = "middleware" ascii nocase
    condition:
        scan_target == "header" and header_name == "x-middleware-subrequest" and $a
}

rule krawl_cve_2025_55182_react2shell {
    meta:
        attack_type = "cve_2025_55182"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "React2Shell: a forged React Server Components Flight payload (prototype chain references or a resolved_model chunk) sent to a Next.js server action to run code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None expected: real server action bodies never reference __proto__ or constructor chains."
        cve = "CVE-2025-55182"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55182"
    strings:
        $proto_then = ":__proto__:then\"" ascii
        $ctor_chain = /"\$[0-9a-fA-F]{1,8}:constructor:constructor"/
        $model = "\"resolved_model\"" ascii
        $lazy = "\"$$typeof\":\"$Lazy\"" ascii
        $proto = "\"__proto__\"" ascii
        $server_ref = /\["\$S[RF]"\s*,\s*"child_process"/
        // __proto__ written as JSON unicode escapes to slip past filters
        $escaped_proto = "\\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f" ascii nocase
        // ["$1:aa:aa"] or {"aa":"$1:aa:aa"}: the public detection probes
        $probe = /[\[:]\s*"\$[0-9]{1,4}:[a-z]{1,8}:[a-z]{1,8}"\s*[\]}]/
    condition:
        scan_target == "body" and (
            $proto_then or $ctor_chain or $server_ref or $probe or $escaped_proto
            or ($proto and ($model or $lazy))
        )
}

rule krawl_cve_2015_7501_jboss_invoker {
    meta:
        attack_type = "cve_2015_7501"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "JBoss Application Server invoker servlets that deserialize attacker-supplied Java objects."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2015-7501"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7501"
    strings:
        $a = "/invoker/JMXInvokerServlet" ascii nocase
        $b = "/invoker/EJBInvokerServlet" ascii nocase
        $c = "/invoker/readonly" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2024_24919_checkpoint_file_read {
    meta:
        attack_type = "cve_2024_24919"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Check Point Security Gateway arbitrary file read: a POST to /clients/MyCRL with an aCSHELL/ prefix followed by traversal."
        mitre_attack = "T1190, T1005"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-24919"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-24919"
    strings:
        $path = "/clients/MyCRL" ascii nocase
        $prefix = "aCSHELL/" ascii nocase
    condition:
        (scan_target == "path" and $path) or (scan_target == "body" and $prefix)
}

rule krawl_cve_2024_1709_screenconnect_setup_wizard {
    meta:
        attack_type = "cve_2024_1709"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "ConnectWise ScreenConnect authentication bypass: a path segment after SetupWizard.aspx reaches the setup wizard on an installed server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; the setup wizard is never requested with a trailing path segment."
        cve = "CVE-2024-1709"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1709"
    strings:
        $a = /\/SetupWizard\.aspx\/[^\s?]/ ascii nocase
    condition:
        scan_target == "path" and $a
}

rule krawl_cve_2024_28995_servu_traversal {
    meta:
        attack_type = "cve_2024_28995"
        classification = "attack"
        severity = 7
        confidence = "high"
        description = "SolarWinds Serv-U directory traversal through the InternalDir and InternalFile parameters."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; the parameters are specific to Serv-U."
        cve = "CVE-2024-28995"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-28995"
    strings:
        $dir = /InternalDir=[^&]{0,60}\.\.[\/\\]/ ascii nocase
        $file = /InternalFile=[^&]{0,60}\.\.[\/\\]/ ascii nocase
    condition:
        scan_target == "query" and any of them
}

rule krawl_cve_2024_23692_rejetto_hfs_template {
    meta:
        attack_type = "cve_2024_23692"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Rejetto HTTP File Server 2.x template injection: {.exec|...} macros in the search parameter run commands."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; HFS macro syntax does not appear in ordinary requests."
        cve = "CVE-2024-23692"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-23692"
    strings:
        $a = /\{\.(exec|save|load|delete)\|/ ascii nocase
    condition:
        (scan_target == "query" or scan_target == "body") and $a
}

rule krawl_cve_2024_4040_crushftp_template {
    meta:
        attack_type = "cve_2024_4040"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "CrushFTP server-side template injection: <INCLUDE> tags or the {working_dir} variable used to read files outside the VFS sandbox."
        mitre_attack = "T1190, T1005"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; the tags are CrushFTP internals."
        cve = "CVE-2024-4040"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4040"
    strings:
        $include = /<INCLUDE>[^<]{1,200}<\/INCLUDE>/ ascii nocase
        $workdir = "{working_dir}" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2024_51567_cyberpanel_upgrademysqlstatus {
    meta:
        attack_type = "cve_2024_51567"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "CyberPanel unauthenticated command injection through the statusfile parameter of upgrademysqlstatus, exploited by ransomware campaigns."
        mitre_attack = "T1190, T1059.004"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-51567"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51567"
    strings:
        $a = "/dataBases/upgrademysqlstatus" ascii nocase
    condition:
        scan_target == "path" and $a
}

rule krawl_cve_2024_0012_panos_auth_bypass {
    meta:
        attack_type = "cve_2024_0012"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "PAN-OS management interface authentication bypass: the X-PAN-AUTHCHECK: off header or a request for ztp_gate.php, chained with CVE-2024-9474 for root command execution."
        mitre_attack = "T1190, T1068"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; the header is internal to PAN-OS."
        cve = "CVE-2024-0012, CVE-2024-9474"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0012, https://nvd.nist.gov/vuln/detail/CVE-2024-9474"
    strings:
        $off = "off" ascii nocase
        $ztp = "/php/ztp_gate.php" ascii nocase
    condition:
        (scan_target == "header" and header_name == "x-pan-authcheck" and $off) or (scan_target == "path" and $ztp)
}

rule krawl_cve_2024_36991_splunk_windows_traversal {
    meta:
        attack_type = "cve_2024_36991"
        classification = "attack"
        severity = 7
        confidence = "high"
        description = "Splunk Enterprise on Windows path traversal through repeated C:../ segments under /modules/messaging/."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known."
        cve = "CVE-2024-36991"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36991"
    strings:
        $a = /\/modules\/messaging\/C:\.\.\// ascii nocase
    condition:
        scan_target == "path" and $a
}

rule krawl_cve_2025_24813_tomcat_partial_put {
    meta:
        attack_type = "cve_2025_24813"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Tomcat partial PUT writing a serialized session file (*.session), later loaded through a JSESSIONID cookie for code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "WebDAV clients uploading a file that happens to end in .session."
        cve = "CVE-2025-24813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24813"
    strings:
        $a = /\.session$/ ascii nocase
    condition:
        http_method == "PUT" and scan_target == "path" and $a
}

rule krawl_cve_2025_3248_langflow_validate_code {
    meta:
        attack_type = "cve_2025_3248"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Langflow unauthenticated code execution: Python code posted to the /api/v1/validate/code endpoint is executed by the server."
        mitre_attack = "T1190, T1059.006"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2025-3248"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-3248"
    strings:
        $a = "/api/v1/validate/code" ascii nocase
    condition:
        scan_target == "path" and $a
}
