#!/usr/bin/env python3

import re
from typing import Optional
from wordlists import get_wordlists


def detect_xss_pattern(input_string: str) -> bool:
    if not input_string:
        return False

    wl = get_wordlists()
    xss_pattern = wl.attack_patterns.get("xss_attempt", "")

    if not xss_pattern:
        xss_pattern = r"(<script|</script|javascript:|onerror=|onload=|onclick=|<iframe|<img|<svg|eval\(|alert\()"

    return bool(re.search(xss_pattern, input_string, re.IGNORECASE))


def generate_xss_response(input_data: dict) -> str:
    xss_detected = False
    reflected_content = []

    for key, value in input_data.items():
        if detect_xss_pattern(value):
            xss_detected = True
        reflected_content.append(f"<p><strong>{key}:</strong> {value}</p>")

    if xss_detected:
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
