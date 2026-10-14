"""wordlists.json attack patterns: real attacks match, ordinary bodies don't.

Cases come from the demo instance's traffic. The old patterns flagged every
JSON body (") and every multipart body (--, ;) as SQL/command injection.
"""

import json
import re
import urllib.parse
from pathlib import Path

import pytest

PATTERNS = json.loads((Path(__file__).parents[1] / "wordlists.json").read_text())[
    "attack_patterns"
]


def detect(path: str, body: str = "") -> set[str]:
    """Same split as the tracker: every type on the path, body without path-only ones."""
    found = {k for k, p in PATTERNS.items() if re.search(p, path, re.I)}
    decoded = urllib.parse.unquote(body)
    found |= {
        k
        for k, p in PATTERNS.items()
        if k not in ("common_probes", "login_attempt") and re.search(p, decoded, re.I)
    }
    return found


@pytest.mark.parametrize(
    "path,body,expected",
    [
        ("/.aws/credentials", "", "common_probes"),
        ("/.ssh/id_ed25519", "", "common_probes"),
        ("/@fs/var/run/secrets/kubernetes.io/serviceaccount/token", "", "common_probes"),
        ("/actuator/env", "", "common_probes"),
        ("/terraform.tfstate", "", "common_probes"),
        ("/..;/WEB-INF/web.xml", "", "path_traversal"),
        ("/..%2F..%2Fproc/self/environ", "", "path_traversal"),
        ("/cgi-bin/php", "<?php echo shell_exec('env'); ?>", "command_injection"),
        ("/", "host=;+echo+GSCAN_CMDI+#", "command_injection"),
        ("/", '["$1:aa:aa"]', "command_injection"),
        ("/api/fs/exec", '{"command":"env","args":[]}', "command_injection"),
        ("/", "id=1'+OR+'1'='1", "sql_injection"),
        ("/read-document", '{"file_path":".env"}', "lfi_rfi"),
        ("/graphql", '{"query":"query IntrospectionQuery{__schema{types{name}}}"}', "scanner_probe"),
        ("/", 'name="junk"\r\n\r\n' + "A" * 300, "scanner_probe"),
    ],
)
def test_attacks_are_detected(path, body, expected):
    assert expected in detect(path, body)


@pytest.mark.parametrize(
    "path,body",
    [
        ("/login", '{"username":"alice","password":"pa\\"ss"}'),
        (
            "/contact-form",
            '------WebKitFormBoundaryX\r\nContent-Disposition: form-data; name="comment"'
            "\r\n\r\njust a form; nothing else -- really\r\n------WebKitFormBoundaryX--",
        ),
        ("/api/v1/profile", '{"id": 5, "name": "O\'Brien", "note": "a; b"}'),
        ("/wp-login.php", "log=admin&pwd=Admin123##&redirect_to=/wp-admin/"),
        ("/document.php", ""),
        ("/about-us", ""),
    ],
)
def test_ordinary_requests_are_not_flagged(path, body):
    noisy = {"sql_injection", "command_injection", "xss_attempt", "xxe_injection"}
    assert not detect(path, body) & noisy
