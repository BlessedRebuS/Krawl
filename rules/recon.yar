// Exposure probes and scanner identities. Every probe path is one that a
// normal visitor never requests on a site that does not expose the product.

rule krawl_probe_credential_files {
    meta:
        attack_type = "credential_file_probe"
        classification = "attack"
        severity = 5
        confidence = "high"
        description = "Request for credential and key files: cloud CLI credentials, SSH private keys, Docker and Kubernetes configs, package-manager tokens, shell histories."
        mitre_attack = "T1552.001, T1595.002"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known; no site legitimately serves these files."
        reference = "https://attack.mitre.org/techniques/T1552/001/"
        response_type = "sensitive_file"
    strings:
        $aws = /\/\.aws\/(credentials|config)/ ascii nocase
        $ssh = /\/(\.ssh\/)?id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/ ascii nocase
        $docker = /\/\.docker(cfg|\/config\.json)/ ascii nocase
        $kube = "/.kube/config" ascii nocase
        $tokens = /\/\.(npmrc|pypirc|netrc|pgpass|git-credentials|s3cfg|boto|bash_history|mysql_history)$/ ascii nocase
        $gcp = /\/(credentials|service[-_]?account|client_secret)[-_a-z0-9]{0,20}\.json$/ ascii nocase
        $tf = "/terraform.tfstate" ascii nocase
        $sel_aws = "/.aws/" ascii nocase
        $sel_ssh_pub = /id_(rsa|dsa|ecdsa|ed25519)\.pub$/ ascii nocase
        $sel_ssh = /id_(rsa|dsa|ecdsa|ed25519)$/ ascii nocase
        $sel_kube = "/.kube/config" ascii nocase
        $sel_docker = "/.docker" ascii nocase
        $sel_npmrc = "/.npmrc" ascii nocase
        $sel_pypirc = "/.pypirc" ascii nocase
        $sel_netrc = "/.netrc" ascii nocase
        $sel_git_credentials = "/.git-credentials" ascii nocase
    condition:
        scan_target == "path" and any of ($aws, $ssh, $docker, $kube, $tokens, $gcp, $tf) and (any of ($sel_*) or true)
}

rule krawl_probe_config_files {
    meta:
        attack_type = "config_file_probe"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Request for application configuration files and editor backups: wp-config backups, .env variants, web.config, appsettings, docker-compose, secrets files."
        mitre_attack = "T1552.001, T1595.002"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known on a site that does not serve its configuration."
        reference = "https://attack.mitre.org/techniques/T1552/001/"
        response_type = "sensitive_file"
    strings:
        $wp = /\/wp-config\.php(~|\.(bak|old|save|orig|txt|zip|swp|copy|backup))$/ ascii nocase
        $cfg = /\/(config|configuration|settings|database|db|local)\.(php|inc|py|rb)(~|\.(bak|old|save|orig|txt|swp|copy|backup))$/ ascii nocase
        $env = /\/\.env\.(local|production|prod|dev|development|staging|backup|bak|save|old|example)$/ ascii nocase
        $web = "/web.config" ascii nocase
        $app = /\/(appsettings(\.[a-z]{1,20})?\.json|application(-[a-z]{1,20})?\.(yml|yaml|properties)|parameters\.yml|database\.yml|secrets\.(json|ya?ml)|config\.json)$/ ascii nocase
        $compose = /\/(docker-compose|compose)\.ya?ml$/ ascii nocase
        $sel_wp_config = "/wp-config.php" ascii nocase
        $sel_dotenv = "/.env." ascii nocase
        $sel_php_config = /(config|configuration|settings|database|db|local)\.(php|inc)/ ascii nocase
    condition:
        scan_target == "path" and any of ($wp, $cfg, $env, $web, $app, $compose) and (any of ($sel_*) or true)
}

rule krawl_probe_backup_archives {
    meta:
        attack_type = "backup_archive_probe"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Request for site or database backup archives under common names (backup.zip, db.sql.gz, www.tar.gz)."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "A site that really publishes a downloadable archive with one of these names."
        reference = "https://attack.mitre.org/techniques/T1213/"
        response_type = "sensitive_file"
    strings:
        $a = /\/(backup|backups|db|database|dump|site|www|wwwroot|web|public_html|html|sql|data|old|bak)\.(zip|tar|tar\.gz|tgz|gz|rar|7z|sql\.gz|sql|bak)$/ ascii nocase
        $sel_sql_dump = /\.sql(\.gz)?$/ ascii nocase
    condition:
        scan_target == "path" and any of ($a) and (any of ($sel_*) or true)
}

rule krawl_probe_vcs_ide {
    meta:
        attack_type = "vcs_ide_probe"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "Request for version-control and IDE metadata: .git/config, .svn entries, .hg, .bzr, CVS, .idea, .vscode, CI configs and .git/HEAD."
        mitre_attack = "T1595.002, T1083"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
        response_type = "vcs_metadata"
    strings:
        $svn = /\/\.svn\/(entries|wc\.db)/ ascii nocase
        $hg = "/.hg/" ascii nocase
        $bzr = "/.bzr/" ascii nocase
        $idea = "/.idea/" ascii nocase
        $vscode = "/.vscode/" ascii nocase
        $cvs = "/CVS/Entries" ascii nocase
        $githead = "/.git/HEAD" ascii nocase
        $ci = /\/\.(gitlab-ci|travis)\.yml$/ ascii nocase
        $git_config = "/.git/config" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_probe_spring_actuator {
    meta:
        attack_type = "actuator_probe"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Request for Spring Boot actuator endpoints that leak configuration or memory (env, heapdump, configprops, jolokia, mappings). Health and info are excluded."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Monitoring that scrapes metrics or loggers from a Spring application."
        reference = "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"
        response_type = "spring_actuator"
    strings:
        $a = /\/actuator\/(env|heapdump|beans|mappings|configprops|loggers|threaddump|httptrace|jolokia|conditions|scheduledtasks|caches|metrics)/ ascii nocase
        $b = /\/actuator\/?$/ ascii nocase
        $c = "/jolokia/" ascii nocase
        $d = "/heapdump" ascii nocase
        $sel_env = "/actuator/env" ascii nocase
    condition:
        scan_target == "path" and any of ($a, $b, $c, $d) and (any of ($sel_*) or true)
}

rule krawl_probe_phpinfo {
    meta:
        attack_type = "phpinfo_probe"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "Request for phpinfo() pages, which disclose PHP version, modules and paths."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Developers testing their own PHP installation."
        reference = "https://www.php.net/manual/en/function.phpinfo.php"
        response_type = "phpinfo"
    strings:
        $p1 = /\/(phpinfo|php_info|info|pi)\.php$/ ascii nocase
        $p2 = "/_profiler/phpinfo" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_probe_server_status {
    meta:
        attack_type = "server_status_probe"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "Request for Apache server-status or server-info, nginx_status or php-fpm status pages that disclose traffic and configuration."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Monitoring agents that scrape these pages (they normally use loopback)."
        reference = "https://httpd.apache.org/docs/2.4/mod/mod_status.html"
        response_type = "server_status"
    strings:
        $a = /\/server-status(\/|$)/ ascii nocase
        $b = /\/server-info(\/|$)/ ascii nocase
        $c = /\/nginx_status(\/|$)/ ascii nocase
        $d = /\/php-fpm-status(\/|$)/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_probe_admin_console {
    meta:
        attack_type = "admin_console_probe"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "Request for management consoles: Tomcat manager, JBoss consoles, Jenkins script console, Werkzeug /console, Druid monitor, Axis2 admin, ColdFusion administrator."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Administrators opening their own consoles."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
    strings:
        $tc = /\/(manager|host-manager)\/(html|text|status)/ ascii nocase
        $jmx = /\/(jmx-console|web-console|admin-console)(\/|$)/ ascii nocase
        $jenkins = /\/(scriptText|jenkins\/script)$/ ascii nocase
        $werk = /\/console\/?$/ ascii nocase
        $druid = /\/druid\/(index|login)\.html/ ascii nocase
        $axis = /\/axis2(\/axis2-admin|-admin)/ ascii nocase
        $cf = "/CFIDE/administrator" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_graphql_introspection {
    meta:
        attack_type = "graphql_introspection"
        classification = "attack"
        severity = 4
        confidence = "high"
        description = "GraphQL introspection query (__schema, IntrospectionQuery) used to map the API before attacking it."
        mitre_attack = "T1595.002, T1590"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "GraphQL developer tools and API documentation generators run against their own endpoint."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"
        response_type = "graphql_schema"
    strings:
        $a = "__schema" ascii nocase
        $b = "IntrospectionQuery" ascii nocase
        $c = "__type(name" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_probe_web_inf {
    meta:
        attack_type = "web_inf_probe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Request for WEB-INF or META-INF content (web.xml, classes, maven metadata) through a path or parameter."
        mitre_attack = "T1595.002, T1083"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; these directories are never served directly."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
        response_type = "java_descriptor"
    strings:
        $web_inf = "/WEB-INF/" ascii nocase
        $meta_inf = "/META-INF/" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_probe_container_api {
    meta:
        attack_type = "container_api_probe"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Request for the Docker Engine, Kubernetes or registry HTTP API over a web port."
        mitre_attack = "T1595.002, T1610"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; container APIs are not served on public web ports."
        reference = "https://docs.docker.com/reference/api/engine/"
        response_type = "container_api"
    strings:
        $d1 = "/containers/json" ascii nocase
        $d2 = "/containers/create" ascii nocase
        $d3 = /\/v1\.[0-9]{2}\/(containers|images|exec)\// ascii nocase
        $k1 = "/api/v1/namespaces" ascii nocase
        $k2 = "/api/v1/pods" ascii nocase
        $reg = "/v2/_catalog" ascii nocase
        $sel_pods = /\/pods(\/|$)/ ascii nocase
    condition:
        scan_target == "path" and any of ($d1, $d2, $d3, $k1, $k2, $reg) and (any of ($sel_*) or true)
}

rule krawl_probe_elasticsearch {
    meta:
        attack_type = "elasticsearch_probe"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Request for Elasticsearch administration and search endpoints (_cat, _cluster, _nodes, _search)."
        mitre_attack = "T1595.002, T1083"
        version = "1.1"
        date = "2026-10-26"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known on a site that is not Elasticsearch."
        reference = "https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html"
        response_type = "elasticsearch"
    strings:
        $cat = "/_cat/" ascii nocase
        $cluster = "/_cluster/" ascii nocase
        $nodes = /\/_nodes(\/|$)/ ascii nocase
        $search = /\/_search(\/|$)/ ascii nocase
        $plugin = "/_plugin/" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_probe_hadoop_yarn {
    meta:
        attack_type = "hadoop_yarn_rce"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "Hadoop YARN ResourceManager application submission (new-application), the entry point of an unauthenticated command execution used by cryptominer botnets."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "None known on a site that is not a Hadoop cluster."
        reference = "https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html"
    strings:
        $a = "/ws/v1/cluster/apps" ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_ua_offensive_tool {
    meta:
        attack_type = "offensive_tool_ua"
        classification = "suspicious"
        severity = 5
        confidence = "high"
        description = "User-Agent of an offensive security tool not covered by the generic scanner rule: exploit frameworks, brute forcers, CMS scanners and fuzzers."
        mitre_attack = "T1595.002"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Authorized penetration tests and bug-bounty researchers; they should be allowlisted by source address."
        reference = "https://attack.mitre.org/techniques/T1595/002/"
    strings:
        $a = /(commix|jaeles|dirsearch|dirbuster|skipfish|arachni|havij|medusa|ncrack|patator|sqlninja|xsstrike)/ ascii nocase
        $b = /(joomscan|droopescan|cmsmap|dalfox|wafw00f|whatweb|gospider|hakrawler)/ ascii nocase
    condition:
        scan_target == "user_agent" and any of them
}

rule krawl_ua_research_scanner {
    meta:
        attack_type = "research_scanner_ua"
        classification = "suspicious"
        severity = 2
        confidence = "high"
        description = "User-Agent of an internet-measurement or exposure-search service (Censys, Shodan, Expanse, Shadowserver, LeakIX, BinaryEdge, ONYPHE). Not hostile by itself, but marks the host as indexed."
        mitre_attack = "T1595"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "These services are research and exposure-monitoring crawlers; treat as informational and allowlist if desired."
        reference = "https://attack.mitre.org/techniques/T1595/"
    strings:
        $a = /(censys|shodan|expanse|shadowserver|leakix|binaryedge|onyphe|criminalip|zoomeye|stretchoid)/ ascii nocase
        $b = /(l9explore|l9tcpid|netsystemsresearch|internet-?measurement)/ ascii nocase
    condition:
        scan_target == "user_agent" and any of them
}

rule krawl_probe_api_docs {
    meta:
        attack_type = "api_docs_probe"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Request for Swagger or OpenAPI documents and UIs, used to map an API's endpoints before attacking them."
        mitre_attack = "T1595.002"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Developers browsing a real API's documentation; none on a site without an API."
        reference = "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        response_type = "api_docs"
    strings:
        $swagger_ui = /\/swagger-ui(\.html|\/)/ ascii nocase
        $swagger_doc = /\/swagger\.(json|ya?ml)$/ ascii nocase
        $openapi = /\/openapi\.(json|ya?ml)$/ ascii nocase
        $springdoc = /\/v[23]\/api-docs/ ascii nocase
        $apidocs = /\/api-docs(\/|$)/ ascii nocase
    condition:
        scan_target == "path" and any of them
}

rule krawl_probe_debug_endpoints {
    meta:
        attack_type = "debug_endpoint_probe"
        classification = "attack"
        severity = 5
        confidence = "high"
        description = "Request for framework debug and profiling endpoints (Go pprof and expvar, Symfony profiler, Laravel Telescope, Django debug toolbar, ASP.NET trace and ELMAH, Rails info) that leak requests, secrets and stack traces."
        mitre_attack = "T1595.002, T1082"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "None known; these endpoints are disabled in production."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
    strings:
        $pprof = "/debug/pprof" ascii nocase
        $expvar = /\/debug\/vars$/ ascii nocase
        $profiler = /\/_profiler(\/|$)/ ascii nocase
        $telescope = "/telescope/requests" ascii nocase
        $djdt = "/__debug__/" ascii nocase
        $aspnet = /\/(trace|elmah)\.axd/ ascii nocase
        $rails = "/rails/info/properties" ascii nocase
    condition:
        scan_target == "path" and any of them
}
