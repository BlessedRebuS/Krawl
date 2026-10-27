rule krawl_scanner_user_agent {
    meta:
        attack_type = "scanner_user_agent"
        classification = "suspicious"
        severity = 4
        confidence = "medium"
        description = "User-Agent of a known vulnerability scanner or offensive tool."
        mitre_attack = "T1595.002"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Security teams and bug-bounty researchers with authorization; the word 'scanner' also appears in some benign barcode or document apps."
        reference = "https://attack.mitre.org/techniques/T1595/002/"
    strings:
        $scanner = "scanner" ascii nocase
        $sqlmap = "sqlmap" ascii nocase
        $nessus = "nessus" ascii nocase
        $burp = "burp" ascii nocase
        $zap = "zaproxy" ascii nocase
        $metasploit = "metasploit" ascii nocase
        $nuclei = "nuclei" ascii nocase
        $gobuster = "gobuster" ascii nocase
        $dirb = "dirb" ascii nocase
        $nikto = "nikto" ascii nocase
        $nmap = "nmap" ascii nocase
        $masscan = "masscan" ascii nocase
        $zgrab = "zgrab" ascii nocase
        $acunetix = "acunetix" ascii nocase
        $w3af = "w3af" ascii nocase
        $wpscan = "wpscan" ascii nocase
        $fuzzers = /(ffuf|wfuzz|feroxbuster)/ ascii nocase
        $hydra = "hydra" ascii nocase
    condition:
        scan_target == "user_agent" and any of them
}
