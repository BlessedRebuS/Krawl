#!/usr/bin/env python3

import re
import random
import logging
import json
from typing import Optional, Tuple, Dict
from generators import random_username, random_password, random_email
from wordlists import get_wordlists

logger = logging.getLogger("krawl")


def detect_path_traversal(path: str, query: str = "", body: str = "") -> bool:
    """Detect path traversal attempts in request"""
    full_input = f"{path} {query} {body}"

    wl = get_wordlists()
    pattern = wl.attack_patterns.get("path_traversal", "")

    if not pattern:
        # Fallback pattern if wordlists not loaded
        pattern = r"(\.\.|%2e%2e|/etc/passwd|/etc/shadow)"

    if re.search(pattern, full_input, re.IGNORECASE):
        logger.debug(f"Path traversal detected in {full_input[:100]}")
        return True
    return False


def detect_xxe_injection(body: str) -> bool:
    """Detect XXE injection attempts in XML payloads"""
    if not body:
        return False

    wl = get_wordlists()
    pattern = wl.attack_patterns.get("xxe_injection", "")

    if not pattern:
        # Fallback pattern if wordlists not loaded
        pattern = r"(<!ENTITY|<!DOCTYPE|SYSTEM|PUBLIC|file://)"

    if re.search(pattern, body, re.IGNORECASE):
        return True
    return False


def detect_command_injection(path: str, query: str = "", body: str = "") -> bool:
    """Detect command injection attempts"""
    full_input = f"{path} {query} {body}"

    logger.debug(
        f"[CMD_INJECTION_CHECK] path='{path}' query='{query}' body='{body[:50] if body else ''}'"
    )
    logger.debug(f"[CMD_INJECTION_CHECK] full_input='{full_input[:200]}'")

    wl = get_wordlists()
    pattern = wl.attack_patterns.get("command_injection", "")

    if not pattern:
        # Fallback pattern if wordlists not loaded
        pattern = r"(cmd=|exec=|command=|&&|;|\||whoami|id|uname|cat|ls)"

    if re.search(pattern, full_input, re.IGNORECASE):
        logger.debug(f"[CMD_INJECTION_CHECK] Command injection pattern matched!")
        return True

    logger.debug(f"[CMD_INJECTION_CHECK] No command injection detected")
    return False


def generate_fake_passwd() -> str:
    """Generate fake /etc/passwd content"""
    wl = get_wordlists()
    passwd_config = wl.fake_passwd

    if not passwd_config:
        # Fallback
        return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"

    users = passwd_config.get("system_users", [])
    uid_min = passwd_config.get("uid_min", 1000)
    uid_max = passwd_config.get("uid_max", 2000)
    gid_min = passwd_config.get("gid_min", 1000)
    gid_max = passwd_config.get("gid_max", 2000)
    shells = passwd_config.get("shells", ["/bin/bash"])

    fake_users = [
        f"{random_username()}:x:{random.randint(uid_min, uid_max)}:{random.randint(gid_min, gid_max)}::/home/{random_username()}:{random.choice(shells)}"
        for _ in range(3)
    ]

    return "\n".join(users + fake_users)


def generate_fake_shadow() -> str:
    """Generate fake /etc/shadow content"""
    wl = get_wordlists()
    shadow_config = wl.fake_shadow

    if not shadow_config:
        # Fallback
        return "root:$6$rounds=656000$fake_salt_here$fake_hash_data:19000:0:99999:7:::"

    entries = shadow_config.get("system_entries", [])
    hash_prefix = shadow_config.get("hash_prefix", "$6$rounds=656000$")
    salt_length = shadow_config.get("salt_length", 16)
    hash_length = shadow_config.get("hash_length", 86)

    fake_entries = [
        f"{random_username()}:{hash_prefix}{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=salt_length))}${''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=hash_length))}:19000:0:99999:7:::"
        for _ in range(3)
    ]

    return "\n".join(entries + fake_entries)


def generate_fake_config_file(filename: str) -> str:
    """Generate fake configuration file content"""
    configs = {
        "config.php": """<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'app_database');
define('DB_USER', 'db_user');
define('DB_PASSWORD', 'fake_pass_123');
define('SECRET_KEY', 'fake_secret_key_xyz789');
define('API_ENDPOINT', 'https://api.example.com');
?>""",
        "application.properties": """# Database Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/appdb
spring.datasource.username=dbuser
spring.datasource.password=fake_password_123
server.port=8080
jwt.secret=fake_jwt_secret_key_456""",
        ".env": """DB_HOST=localhost
DB_PORT=3306
DB_NAME=production_db
DB_USER=app_user
DB_PASSWORD=fake_env_password_789
API_KEY=fake_api_key_abc123
SECRET_TOKEN=fake_secret_token_xyz""",
    }

    for key in configs:
        if key.lower() in filename.lower():
            return configs[key]

    return f"""# Configuration File
api_endpoint = https://api.example.com
api_key = fake_key_{random.randint(1000, 9999)}
database_url = mysql://user:fake_pass@localhost/db
secret = fake_secret_{random.randint(10000, 99999)}
"""


def generate_fake_directory_listing(path: str) -> str:
    """Generate fake directory listing"""
    wl = get_wordlists()
    dir_config = wl.directory_listing

    if not dir_config:
        # Fallback
        return f"<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1></body></html>"

    fake_dirs = dir_config.get("fake_directories", [])
    fake_files = dir_config.get("fake_files", [])

    directories = [(d["name"], d["size"], d["perms"]) for d in fake_dirs]
    files = [
        (f["name"], str(random.randint(f["size_min"], f["size_max"])), f["perms"])
        for f in fake_files
    ]

    html = f"<html><head><title>Index of {path}</title></head><body>"
    html += f"<h1>Index of {path}</h1><hr><pre>"
    html += f"{'Name':<40} {'Size':<10} {'Permissions':<15}\n"
    html += "-" * 70 + "\n"

    for name, size, perms in directories:
        html += f"{name + '/':<40} {size:<10} {perms:<15}\n"

    for name, size, perms in files:
        html += f"{name:<40} {size:<10} {perms:<15}\n"

    html += "</pre><hr></body></html>"
    return html


def generate_path_traversal_response(path: str) -> Tuple[str, str, int]:
    """Generate fake response for path traversal attempts"""

    path_lower = path.lower()
    logger.debug(f"Generating path traversal response for: {path}")

    if "passwd" in path_lower:
        logger.debug("Returning fake passwd file")
        return (generate_fake_passwd(), "text/plain", 200)

    if "shadow" in path_lower:
        logger.debug("Returning fake shadow file")
        return (generate_fake_shadow(), "text/plain", 200)

    if any(
        ext in path_lower for ext in [".conf", ".config", ".php", ".env", ".properties"]
    ):
        logger.debug("Returning fake config file")
        return (generate_fake_config_file(path), "text/plain", 200)

    if "proc/self" in path_lower:
        logger.debug("Returning fake proc info")
        return (f"{random.randint(1000, 9999)}", "text/plain", 200)

    logger.debug("Returning fake directory listing")
    return (generate_fake_directory_listing(path), "text/html", 200)


def generate_xxe_response(body: str) -> Tuple[str, str, int]:
    """Generate fake response for XXE injection attempts"""
    wl = get_wordlists()
    xxe_config = wl.xxe_responses

    if "file://" in body:
        if "passwd" in body:
            content = generate_fake_passwd()
        elif "shadow" in body:
            content = generate_fake_shadow()
        else:
            content = (
                xxe_config.get("default_content", "root:x:0:0:root:/root:/bin/bash")
                if xxe_config
                else "root:x:0:0:root:/root:/bin/bash"
            )

        if xxe_config and "file_access" in xxe_config:
            template = xxe_config["file_access"]["template"]
            response = template.replace("{content}", content)
        else:
            response = f"""<?xml version="1.0"?>
<response>
    <status>success</status>
    <data>{content}</data>
</response>"""
        return (response, "application/xml", 200)

    if "ENTITY" in body:
        if xxe_config and "entity_processed" in xxe_config:
            template = xxe_config["entity_processed"]["template"]
            entity_values = xxe_config["entity_processed"]["entity_values"]
            entity_value = random.choice(entity_values)
            response = template.replace("{entity_value}", entity_value)
        else:
            response = """<?xml version="1.0"?>
<response>
    <status>success</status>
    <message>Entity processed successfully</message>
    <entity_value>fake_entity_content_12345</entity_value>
</response>"""
        return (response, "application/xml", 200)

    if xxe_config and "error" in xxe_config:
        template = xxe_config["error"]["template"]
        messages = xxe_config["error"]["messages"]
        message = random.choice(messages)
        response = template.replace("{message}", message)
    else:
        response = """<?xml version="1.0"?>
<response>
    <status>error</status>
    <message>External entity processing disabled</message>
</response>"""
    return (response, "application/xml", 200)


def generate_command_injection_response(input_text: str) -> Tuple[str, str, int]:
    """Generate fake command execution output"""
    wl = get_wordlists()
    cmd_config = wl.command_outputs

    input_lower = input_text.lower()

    # id command
    if re.search(r"\bid\b", input_lower):
        if cmd_config and "id" in cmd_config:
            uid = random.randint(
                cmd_config.get("uid_min", 1000), cmd_config.get("uid_max", 2000)
            )
            gid = random.randint(
                cmd_config.get("gid_min", 1000), cmd_config.get("gid_max", 2000)
            )
            template = random.choice(cmd_config["id"])
            output = template.replace("{uid}", str(uid)).replace("{gid}", str(gid))
        else:
            output = f"uid={random.randint(1000, 2000)}(www-data) gid={random.randint(1000, 2000)}(www-data) groups={random.randint(1000, 2000)}(www-data)"
        return (output, "text/plain", 200)

    # whoami command
    if re.search(r"\bwhoami\b", input_lower):
        users = cmd_config.get("whoami", ["www-data"]) if cmd_config else ["www-data"]
        return (random.choice(users), "text/plain", 200)

    # uname command
    if re.search(r"\buname\b", input_lower):
        outputs = (
            cmd_config.get("uname", ["Linux server 5.4.0 x86_64"])
            if cmd_config
            else ["Linux server 5.4.0 x86_64"]
        )
        return (random.choice(outputs), "text/plain", 200)

    # pwd command
    if re.search(r"\bpwd\b", input_lower):
        paths = (
            cmd_config.get("pwd", ["/var/www/html"])
            if cmd_config
            else ["/var/www/html"]
        )
        return (random.choice(paths), "text/plain", 200)

    # ls command
    if re.search(r"\bls\b", input_lower):
        if cmd_config and "ls" in cmd_config:
            files = random.choice(cmd_config["ls"])
        else:
            files = ["index.php", "config.php", "uploads"]
        output = "\n".join(
            random.sample(files, k=random.randint(3, min(6, len(files))))
        )
        return (output, "text/plain", 200)

    # cat command
    if re.search(r"\bcat\b", input_lower):
        if "passwd" in input_lower:
            return (generate_fake_passwd(), "text/plain", 200)
        if "shadow" in input_lower:
            return (generate_fake_shadow(), "text/plain", 200)
        cat_content = (
            cmd_config.get("cat_config", "<?php\n$config = 'fake';\n?>")
            if cmd_config
            else "<?php\n$config = 'fake';\n?>"
        )
        return (cat_content, "text/plain", 200)

    # echo command
    if re.search(r"\becho\b", input_lower):
        match = re.search(r"echo\s+(.+?)(?:[;&|]|$)", input_text, re.IGNORECASE)
        if match:
            return (match.group(1).strip("\"'"), "text/plain", 200)
        return ("", "text/plain", 200)

    # network commands
    if any(cmd in input_lower for cmd in ["wget", "curl", "nc", "netcat"]):
        if cmd_config and "network_commands" in cmd_config:
            outputs = cmd_config["network_commands"]
            output = random.choice(outputs)
            if "{size}" in output:
                size = random.randint(
                    cmd_config.get("download_size_min", 100),
                    cmd_config.get("download_size_max", 10000),
                )
                output = output.replace("{size}", str(size))
        else:
            outputs = ["bash: command not found", "Connection timeout"]
            output = random.choice(outputs)
        return (output, "text/plain", 200)

    # generic outputs
    if cmd_config and "generic" in cmd_config:
        generic_outputs = cmd_config["generic"]
        output = random.choice(generic_outputs)
        if "{num}" in output:
            output = output.replace("{num}", str(random.randint(1, 99)))
    else:
        generic_outputs = ["", "Command executed successfully", "sh: syntax error"]
        output = random.choice(generic_outputs)

    return (output, "text/plain", 200)


def detect_sql_injection_pattern(query_string: str) -> Optional[str]:
    """Detect SQL injection patterns in query string"""
    if not query_string:
        return None

    query_lower = query_string.lower()

    patterns = {
        "quote": [r"'", r'"', r"`"],
        "comment": [r"--", r"#", r"/\*", r"\*/"],
        "union": [r"\bunion\b", r"\bunion\s+select\b"],
        "boolean": [r"\bor\b.*=.*", r"\band\b.*=.*", r"'.*or.*'.*=.*'"],
        "time_based": [r"\bsleep\b", r"\bwaitfor\b", r"\bdelay\b", r"\bbenchmark\b"],
        "stacked": [r";.*select", r";.*drop", r";.*insert", r";.*update", r";.*delete"],
        "command": [r"\bexec\b", r"\bexecute\b", r"\bxp_cmdshell\b"],
        "info_schema": [r"information_schema", r"table_schema", r"table_name"],
    }

    for injection_type, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, query_lower):
                logger.debug(f"SQL injection pattern '{injection_type}' detected")
                return injection_type

    return None


def get_random_sql_error(
    db_type: str = None, injection_type: str = None
) -> Tuple[str, str]:
    """Generate a random SQL error message"""
    wl = get_wordlists()
    sql_errors = wl.sql_errors

    if not sql_errors:
        return ("Database error occurred", "text/plain")

    if not db_type:
        db_type = random.choice(list(sql_errors.keys()))

    db_errors = sql_errors.get(db_type, {})

    if injection_type and injection_type in db_errors:
        errors = db_errors[injection_type]
    elif "generic" in db_errors:
        errors = db_errors["generic"]
    else:
        all_errors = []
        for error_list in db_errors.values():
            if isinstance(error_list, list):
                all_errors.extend(error_list)
        errors = all_errors if all_errors else ["Database error occurred"]

    error_message = random.choice(errors) if errors else "Database error occurred"

    if "{table}" in error_message:
        tables = ["users", "products", "orders", "customers", "accounts", "sessions"]
        error_message = error_message.replace("{table}", random.choice(tables))

    if "{column}" in error_message:
        columns = ["id", "name", "email", "password", "username", "created_at"]
        error_message = error_message.replace("{column}", random.choice(columns))

    return (error_message, "text/plain")


def generate_sql_error_response(
    query_string: str, db_type: str = None
) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Generate SQL error response for detected injection attempts"""
    injection_type = detect_sql_injection_pattern(query_string)

    if not injection_type:
        return (None, None, None)

    error_message, content_type = get_random_sql_error(db_type, injection_type)

    status_code = 500

    if random.random() < 0.3:
        status_code = 200

    logger.info(f"SQL injection detected: {injection_type}")
    return (error_message, content_type, status_code)


def get_sql_response_with_data(path: str, params: str) -> str:
    """Generate fake SQL query response with data"""
    injection_type = detect_sql_injection_pattern(params)

    if injection_type in ["union", "boolean", "stacked"]:
        data = {
            "success": True,
            "results": [
                {
                    "id": i,
                    "username": random_username(),
                    "email": random_email(),
                    "password_hash": random_password(),
                    "role": random.choice(["admin", "user", "moderator"]),
                }
                for i in range(1, random.randint(2, 5))
            ],
        }
        return json.dumps(data, indent=2)

    return json.dumps(
        {"success": True, "message": "Query executed successfully", "results": []},
        indent=2,
    )


def detect_xss_pattern(input_string: str) -> bool:
    """Detect XSS patterns in input"""
    if not input_string:
        return False

    wl = get_wordlists()
    xss_pattern = wl.attack_patterns.get("xss_attempt", "")

    if not xss_pattern:
        xss_pattern = r"(<script|</script|javascript:|onerror=|onload=|onclick=|<iframe|<img|<svg|eval\(|alert\()"

    detected = bool(re.search(xss_pattern, input_string, re.IGNORECASE))
    if detected:
        logger.debug(f"XSS pattern detected in input")
    return detected


def generate_xss_response(input_data: dict) -> str:
    """Generate response for XSS attempts with reflected content"""
    xss_detected = False
    reflected_content = []

    for key, value in input_data.items():
        if detect_xss_pattern(value):
            xss_detected = True
        reflected_content.append(f"<p><strong>{key}:</strong> {value}</p>")

    if xss_detected:
        logger.info("XSS attempt detected and reflected")
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Submission Received</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .success {{ background: #d4edda; padding: 20px; border-radius: 8px; border: 1px solid #c3e6cb; }}
        h2 {{ color: #155724; }}
        p {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="success">
        <h2>Thank you for your submission!</h2>
        <p>We have received your information:</p>
        {''.join(reflected_content)}
        <p><em>We will get back to you shortly.</em></p>
    </div>
</body>
</html>
"""
        return html

    return """
<!DOCTYPE html>
<html>
<head>
    <title>Submission Received</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .success { background: #d4edda; padding: 20px; border-radius: 8px; border: 1px solid #c3e6cb; }
        h2 { color: #155724; }
    </style>
</head>
<body>
    <div class="success">
        <h2>Thank you for your submission!</h2>
        <p>Your message has been received and we will respond soon.</p>
    </div>
</body>
</html>
"""


def generate_server_error() -> Tuple[str, str]:
    """Generate fake server error page"""
    wl = get_wordlists()
    server_errors = wl.server_errors

    if not server_errors:
        return ("500 Internal Server Error", "text/html")

    server_type = random.choice(list(server_errors.keys()))
    server_config = server_errors[server_type]

    error_codes = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }

    code = random.choice(list(error_codes.keys()))
    message = error_codes[code]

    template = server_config.get("template", "")
    version = random.choice(server_config.get("versions", ["1.0"]))

    html = template.replace("{code}", str(code))
    html = html.replace("{message}", message)
    html = html.replace("{version}", version)

    if server_type == "apache":
        os = random.choice(server_config.get("os", ["Ubuntu"]))
        html = html.replace("{os}", os)
        html = html.replace("{host}", "localhost")

    logger.debug(f"Generated {server_type} server error: {code}")
    return (html, "text/html")


def get_server_header(server_type: str = None) -> str:
    """Get a fake server header string"""
    wl = get_wordlists()
    server_errors = wl.server_errors

    if not server_errors:
        return "nginx/1.18.0"

    if not server_type:
        server_type = random.choice(list(server_errors.keys()))

    server_config = server_errors.get(server_type, {})
    version = random.choice(server_config.get("versions", ["1.0"]))

    server_headers = {
        "nginx": f"nginx/{version}",
        "apache": f"Apache/{version}",
        "iis": f"Microsoft-IIS/{version}",
        "tomcat": f"Apache-Coyote/1.1",
    }

    return server_headers.get(server_type, "nginx/1.18.0")


def detect_and_respond_deception(
    path: str, query: str = "", body: str = "", method: str = "GET"
) -> Optional[Tuple[str, str, int]]:
    """
    Main deception detection and response function.
    Returns (response_body, content_type, status_code) if deception should be applied, None otherwise.
    """

    logger.debug(
        f"Checking deception for {method} {path} query={query[:50] if query else 'empty'}"
    )

    if detect_path_traversal(path, query, body):
        logger.info(f"Path traversal detected in: {path}")
        return generate_path_traversal_response(f"{path}?{query}" if query else path)

    if body and detect_xxe_injection(body):
        logger.info(f"XXE injection detected")
        return generate_xxe_response(body)

    if detect_command_injection(path, query, body):
        logger.info(f"Command injection detected in: {path}")
        full_input = f"{path} {query} {body}"
        return generate_command_injection_response(full_input)

    return None
