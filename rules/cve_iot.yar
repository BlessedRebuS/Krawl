// Routers, cameras and other embedded devices. Mirai-family botnets send these
// requests to any host, so they are the most common exploit traffic a
// honeypot sees. Rules key on the vendor-specific path or parameter.

rule krawl_cve_2018_10561_gpon_router {
    meta:
        attack_type = "cve_2018_10561"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Dasan GPON home router authentication bypass and diag_Form command injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2018-10561, CVE-2018-10562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-10561, https://nvd.nist.gov/vuln/detail/CVE-2018-10562"
    strings:
        $a = "/GponForm/diag_Form" ascii nocase
        $b = "/GponForm/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2017_17215_huawei_hg532 {
    meta:
        attack_type = "cve_2017_17215"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Huawei HG532 UPnP firmware upgrade command injection (Satori and Mirai variants)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2017-17215"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17215"
    strings:
        $a = "/ctrlt/DeviceUpgrade_1" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2014_8361_realtek_sdk_miniigd {
    meta:
        attack_type = "cve_2014_8361"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Realtek SDK miniigd UPnP SOAP command injection, reached through picsdesc.xml and WANIPConnection actions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2014-8361"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8361"
    strings:
        $a = "/picsdesc.xml" ascii nocase
        $b = "urn:schemas-upnp-org:service:WANIPConnection" ascii nocase
        $c = "NewInternalClient" ascii
    condition:
        (scan_target == "path" and $a) or (scan_target == "body" and ($b or $c))
}

rule krawl_cve_2021_36260_hikvision_weblanguage {
    meta:
        attack_type = "cve_2021_36260"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Hikvision IP camera web server command injection through PUT /SDK/webLanguage."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2021-36260"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"
    strings:
        $a = "/SDK/webLanguage" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2017_7921_hikvision_auth_backdoor {
    meta:
        attack_type = "cve_2017_7921"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Hikvision camera authentication bypass using the fixed auth value YWRtaW46MTEK."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2017-7921"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7921"
    strings:
        $a = "auth=YWRtaW46MTEK" ascii
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2022_30525_zyxel_ztp {
    meta:
        attack_type = "cve_2022_30525"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Zyxel firewall zero-touch provisioning command injection at /ztp/cgi-bin/handler."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2022-30525"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30525"
    strings:
        $a = "/ztp/cgi-bin/handler" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2017_18368_zyxel_viewlog {
    meta:
        attack_type = "cve_2017_18368"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Zyxel P660HN-T ViewLog.asp remote_host command injection used by Mirai variants."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2017-18368"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-18368"
    strings:
        $a = "/cgi-bin/ViewLog.asp" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2023_1389_tplink_archer_locale {
    meta:
        attack_type = "cve_2023_1389"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "TP-Link Archer AX21 locale country parameter command injection (Mirai)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2023-1389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1389"
    strings:
        $a = "/locale?form=country" ascii nocase
        $b = "form=country&operation=write" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2016_6277_netgear_cgi_bin_semicolon {
    meta:
        attack_type = "cve_2016_6277"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Netgear R-series routers: shell commands after /cgi-bin/; in the URL path."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2016-6277"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-6277"
    strings:
        $a = "/cgi-bin/;" ascii
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_8515_draytek_mainfunction {
    meta:
        attack_type = "cve_2020_8515"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "DrayTek Vigor mainfunction.cgi keyPath/command injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2020-8515, CVE-2020-15415"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8515, https://nvd.nist.gov/vuln/detail/CVE-2020-15415"
    strings:
        $a = "/cgi-bin/mainfunction.cgi" ascii nocase
        $b = "keyPath=" ascii nocase
    condition:
        (scan_target == "path" and $a) or ((scan_target == "query" or scan_target == "body") and $b)
}

rule krawl_cve_2021_33044_dahua_rpc2_login {
    meta:
        attack_type = "cve_2021_33044"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Dahua camera identity authentication bypass at /RPC2_Login."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2021-33044"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-33044"
    strings:
        $a = "/RPC2_Login" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2021_35395_realtek_boa_goform {
    meta:
        attack_type = "cve_2021_35395"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Realtek Jungle SDK boa web server formPing, formTracert and formWsc command injection (Mirai variants)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2021-35395"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35395"
    strings:
        $a = "/boaform/admin/formPing" ascii nocase
        $b = "/boaform/admin/formTracert" ascii nocase
        $c = "/boaform/formWsc" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_10987_tenda_goform {
    meta:
        attack_type = "cve_2020_10987"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Tenda AC15 goform setUsbUnload command injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2020-10987"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10987"
    strings:
        $a = "/goform/setUsbUnload" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_iot_linksys_tmunblock {
    meta:
        attack_type = "linksys_tmunblock"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Linksys E-series tmUnblock.cgi and hndUnblock.cgi command injection (TheMoon worm)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
    strings:
        $a = "/tmUnblock.cgi" ascii nocase
        $b = "/hndUnblock.cgi" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_iot_dlink_hnap {
    meta:
        attack_type = "dlink_hnap"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "D-Link HNAP SOAPAction header carrying shell metacharacters (command injection through the action name)."
        mitre_attack = "T1190, T1059.004"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
    strings:
        $a = /GetDeviceSettings\/[^ ]{0,20}[`;|$]/ ascii nocase
    condition:
        scan_target == "header" and header_name == "soapaction" and $a
}

rule krawl_cve_2024_3273_dlink_nas_sharing {
    meta:
        attack_type = "cve_2024_3273"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "D-Link NAS backdoor account and command injection through nas_sharing.cgi (user=messagebus with a base64 system parameter)."
        mitre_attack = "T1190, T1059.004"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2024-3273"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3273"
    strings:
        $path = "/cgi-bin/nas_sharing.cgi" ascii nocase
        $user = "user=messagebus" ascii nocase
    condition:
        (scan_target == "path" and $path) or (scan_target == "query" and $user)
}

rule krawl_cve_2024_7029_avtech_brightness {
    meta:
        attack_type = "cve_2024_7029"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "AVTECH IP camera command injection through the brightness parameter of Factory.cgi, spread by Corona Mirai."
        mitre_attack = "T1190, T1059.004"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; these endpoints exist only on the vendor device and are not requested by normal web clients."
        cve = "CVE-2024-7029"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7029"
    strings:
        $path = "/cgi-bin/supervisor/Factory.cgi" ascii nocase
        $param = /brightness=[^&]{0,20}(;|\||`|\$\()/ ascii nocase
    condition:
        (scan_target == "path" and $path) or ((scan_target == "query" or scan_target == "body") and $param)
}
