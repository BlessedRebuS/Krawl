// Requests for webshell paths and uploads of server-side scripts.

rule krawl_webshell_path {
    meta:
        attack_type = "webshell_probe"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Request for a well-known webshell filename, or for a script inside an upload directory where no script should exist."
        mitre_attack = "T1505.003, T1595.002"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "A site that legitimately serves scripts from an uploads directory or has a file named shell.php."
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        response_type = "webshell"
    strings:
        $known = /\/(c99|c100|r57|wso|b374k|alfa|p0wny|indoxploit|weevely|marijuana|filesman|ajaxshell|webshell|backdoor)[a-z0-9_-]{0,10}\.(php|phtml|asp|aspx|jsp|jspx)$/ ascii nocase
        $generic = /\/(shell|cmd|eval|uploader|bypass)\.(php|phtml|asp|aspx|jsp|jspx)$/ ascii nocase
        $upload = /\/(wp-content\/uploads|uploads?|images|files|tmp|cache)\/([A-Za-z0-9._-]{1,40}\/){0,4}[A-Za-z0-9._-]{1,60}\.(php[0-9]?|phtml|jspx?|aspx?)$/ ascii nocase
        $aspnet = /\/aspnet_client\/([A-Za-z0-9._-]{1,40}\/){0,4}[A-Za-z0-9._-]{1,60}\.aspx$/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_webshell_upload {
    meta:
        attack_type = "webshell_upload"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "HTTP PUT, MOVE or COPY of a server-side script (PHP, JSP, ASP) to the web root, the WebDAV upload route to a webshell."
        mitre_attack = "T1505.003, T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Content editors who publish scripts to a development server over WebDAV."
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /\.(php[0-9]?|phtml|jspx?|aspx?|war|cgi)$/ ascii nocase
    condition:
        (http_method == "PUT" or http_method == "MOVE" or http_method == "COPY") and scan_target == "path" and $a
}
