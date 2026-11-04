// Serialized-object markers for Java, JSON type hints, PHP, .NET and Python.
// A marker is evidence of an attempted gadget chain, never proof; confidence
// stays medium because legitimate applications also exchange serialized data.

rule krawl_deser_java {
    meta:
        attack_type = "java_deserialization"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Java serialized object stream (base64 rO0AB, hex aced0005) or well-known gadget class names, in any request field including cookies."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Java applications that exchange serialized objects over HTTP on purpose (JSF ViewState, legacy RMI-over-HTTP)."
        reference = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    strings:
        $b64 = "rO0AB" ascii
        $hex = "aced0005" ascii nocase
        $g1 = "org.apache.commons.collections.functors" ascii nocase
        $g2 = "ysoserial" ascii nocase
        $g3 = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" ascii
    condition:
        any of them
}

rule krawl_deser_json {
    meta:
        attack_type = "json_deserialization"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "JSON polymorphic type hints (fastjson/Jackson @type) naming gadget classes such as JdbcRowSetImpl."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known."
        reference = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    strings:
        $a = /"@type"\s*:\s*"(com\.sun|java\.|javax\.|org\.apache|com\.alibaba|org\.springframework)/ ascii nocase
        $b = "com.sun.rowset.JdbcRowSetImpl" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_deser_php {
    meta:
        attack_type = "php_deserialization"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PHP serialized object (O:length:ClassName:count:{...) supplied in a parameter, the entry point for PHP gadget chains."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Applications that pass serialized PHP objects in a parameter (older plugins)."
        reference = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    strings:
        $a = /O:[0-9]{1,3}:"[A-Za-z_\\][A-Za-z0-9_\\]{1,80}":[0-9]{1,3}:\{/ ascii
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_deser_dotnet {
    meta:
        attack_type = "dotnet_deserialization"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = ".NET BinaryFormatter header (base64 AAEAAAD/////) or well-known gadget types such as ObjectDataProvider."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legacy ASP.NET applications that store BinaryFormatter data in hidden fields."
        reference = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    strings:
        $a = "AAEAAAD/////" ascii
        $b = "System.Windows.Data.ObjectDataProvider" ascii nocase
        $c = "TypeConfuseDelegate" ascii
    condition:
        any of them
}

rule krawl_deser_python_pickle {
    meta:
        attack_type = "python_pickle"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Python pickle opcodes calling os.system, subprocess or eval (protocol 0 text form)."
        mitre_attack = "T1190, T1059.006"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known."
        reference = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    strings:
        $a = "cposix\nsystem\n" ascii
        $b = "cos\nsystem\n" ascii
        $c = "c__builtin__\neval" ascii
        $d = "csubprocess\n" ascii
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}
