// PHP applications and CMS plugins that scanners and botnets exploit at scale.
// Indicators follow the NVD entries and vendor advisories in each reference.

rule krawl_cve_2017_9841_phpunit_eval_stdin {
    meta:
        attack_type = "cve_2017_9841"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "PHPUnit eval-stdin.php exposed under vendor/, executing PHP code from the request body."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2017-9841"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9841"
    strings:
        $a = "phpunit/src/util/php/eval-stdin.php" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2012_1823_php_cgi_argument {
    meta:
        attack_type = "cve_2012_1823"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "PHP-CGI query string treated as command-line options (-d allow_url_include, auto_prepend_file), including the Windows soft-hyphen variant."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2012-1823, CVE-2024-4577"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1823, https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
    strings:
        $a = "allow_url_include" ascii nocase
        $b = "auto_prepend_file" ascii nocase
        $c = "%ADd" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_cve_2018_20062_thinkphp_rce {
    meta:
        attack_type = "cve_2018_20062"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "ThinkPHP invokefunction / method-override remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2018-20062, CVE-2019-9082"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20062, https://nvd.nist.gov/vuln/detail/CVE-2019-9082"
    strings:
        $a = "\\think\\app" ascii nocase
        $b = "invokefunction" ascii nocase
        $c = "_method=__construct" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2021_3129_laravel_ignition {
    meta:
        attack_type = "cve_2021_3129"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Laravel Ignition execute-solution endpoint abused for file write and code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Laravel developers debugging their own application with Ignition enabled."
        cve = "CVE-2021-3129"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3129"
    strings:
        $a = "/_ignition/execute-solution" ascii nocase
        $b = "MakeViewVariableOptionalSolution" ascii
        $c = "convert.quoted-printable-decode" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2018_7600_drupalgeddon2 {
    meta:
        attack_type = "cve_2018_7600"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Drupalgeddon2 render-array injection through #post_render, #markup, #lazy_builder or element_parents."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2018-7600, CVE-2018-7602"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7600, https://nvd.nist.gov/vuln/detail/CVE-2018-7602"
    strings:
        $a = "[#post_render]" ascii nocase
        $b = "[#markup]" ascii nocase
        $c = "[#lazy_builder]" ascii nocase
        $d = "element_parents=account/mail" ascii nocase
        $e = "[#access_callback]" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2015_8562_joomla_object_injection {
    meta:
        attack_type = "cve_2015_8562"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Joomla session object injection: serialized PHP object after a }__ marker in User-Agent or other headers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2015-8562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8562"
    strings:
        $a = /\}__[a-z]{1,10}\|O:[0-9]{1,3}:"/ ascii
    condition:
        (scan_target == "user_agent" or scan_target == "header") and $a
}

rule krawl_cve_2023_23752_joomla_config_disclosure {
    meta:
        attack_type = "cve_2023_23752"
        classification = "attack"
        severity = 7
        confidence = "high"
        description = "Joomla improper access check exposing application configuration through the public REST API."
        mitre_attack = "T1190, T1552.001"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-23752"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23752"
        response_type = "joomla_config"
    strings:
        $a = "/api/index.php/v1/config/application" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_25213_wp_file_manager {
    meta:
        attack_type = "cve_2020_25213"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "WordPress File Manager plugin connector.minimal.php unauthenticated upload and command execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-25213"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25213"
    strings:
        $a = "/wp-file-manager/lib/php/connector" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2020_11738_wp_duplicator {
    meta:
        attack_type = "cve_2020_11738"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "WordPress Duplicator plugin arbitrary file download via the duplicator_download action."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2020-11738"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11738"
    strings:
        $a = "action=duplicator_download" ascii nocase
    condition:
        (scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2024_27956_wp_automatic_sqli {
    meta:
        attack_type = "cve_2024_27956"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "WP Automatic plugin csv.php SQL injection used to create an administrator account."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-27956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27956"
    strings:
        $a = "/wp-automatic/inc/csv.php" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2019_9978_wp_social_warfare {
    meta:
        attack_type = "cve_2019_9978"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Social Warfare plugin swp_debug parameter loading a remote file for code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-9978"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9978"
    strings:
        $a = "swp_debug=load_options" ascii nocase
        $b = "swp_url=" ascii nocase
    condition:
        scan_target == "query" and any of them
}

rule krawl_cve_2023_6553_wp_backup_migration {
    meta:
        attack_type = "cve_2023_6553"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Backup Migration plugin backup-heart.php include injection through the content-dir header."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-6553"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6553"
    strings:
        $a = "/backup-backup/includes/backup-heart.php" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_cve_2024_10924_wp_really_simple_security {
    meta:
        attack_type = "cve_2024_10924"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Really Simple Security two-factor REST authentication bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2024-10924"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10924"
    strings:
        $a = "reallysimplessl/v1/two_fa" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_wordpress_xmlrpc_multicall {
    meta:
        attack_type = "wp_xmlrpc_multicall"
        classification = "attack"
        severity = 6
        confidence = "high"
        description = "WordPress xmlrpc.php system.multicall used to try many passwords in one request, bypassing per-request login throttling."
        mitre_attack = "T1110.001"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; real clients rarely call system.multicall with wp.getUsersBlogs."
        reference = "https://wordpress.org/support/article/hardening-wordpress/"
    strings:
        $a = "system.multicall" ascii nocase
        $b = "wp.getUsersBlogs" ascii nocase
    condition:
        scan_target == "body" and $a and $b
}

rule krawl_cve_2019_16759_vbulletin_widget_php {
    meta:
        attack_type = "cve_2019_16759"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "vBulletin widget_php routestring remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2019-16759"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16759"
    strings:
        $a = "ajax/render/widget_php" ascii nocase
        $b = "widgetConfig[code]" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2023_41892_craft_cms_conditions {
    meta:
        attack_type = "cve_2023_41892"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Craft CMS conditions/render action with a configObject used for remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate use of the product by its own administrators; unlikely from internet clients of a honeypot."
        cve = "CVE-2023-41892"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41892"
    strings:
        $a = "conditions/render" ascii nocase
        $b = "configObject=craft" ascii nocase
    condition:
        (scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_cve_2024_25600_wp_bricks_render_element {
    meta:
        attack_type = "cve_2024_25600"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Bricks Builder for WordPress unauthenticated code execution through the render_element REST endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Editors of a real Bricks site previewing elements; unlikely on a honeypot."
        cve = "CVE-2024-25600"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-25600"
    strings:
        $a = "bricks/v1/render_element" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and $a
}

rule krawl_cve_2021_24284_wp_kaswara_upload {
    meta:
        attack_type = "cve_2021_24284"
        classification = "attack"
        severity = 10
        confidence = "high"
        description = "Kaswara Modern WPBakery Addons unauthenticated file upload through the uploadFontIcon AJAX action."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; the plugin was abandoned and the action is only requested by scanners."
        cve = "CVE-2021-24284"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-24284"
    strings:
        $a = "action=uploadFontIcon" ascii nocase
    condition:
        (scan_target == "query" or scan_target == "body") and $a
}
