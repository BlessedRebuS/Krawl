#!/usr/bin/env python3

import random
from wordlists import get_wordlists


def generate_server_error() -> tuple[str, str]:
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

    return (html, "text/html")


def get_server_header(server_type: str = None) -> str:
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
