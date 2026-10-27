"""The bundled catalogue answers each kind of attack with matching fake content.

Requests go through the bundled YARA rules and the bundled response catalogue,
the same decision the deception middleware makes.
"""

import re
import shutil
import sys
import urllib.parse
from pathlib import Path

import pytest

from detection import DetectionCoordinator, YaraDetectionEngine
from responses import ResponseCatalog

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
RESPONSES = ROOT / "responses"

sys.path.insert(0, str(ROOT / "scripts"))

from fake_attacks import ATTACKS, BENIGN  # noqa: E402


@pytest.fixture(scope="module")
def detector():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


@pytest.fixture(scope="module")
def catalog():
    return ResponseCatalog.load(RESPONSES)


def _answer(detector, catalog, method, path, query, body):
    findings = detector.scan_request(path=path, query=query, body=body, method=method)
    return catalog.select(findings, method, path, query)


# (method, path, query, body, marker): the reply must contain marker.
CASES = [
    ("GET", "/etc/passwd", "", "", "root:x:0:0"),
    ("GET", "/x", "file=../../etc/shadow", "", "root:$6$"),
    ("GET", "/download", "file=..\\..\\windows\\win.ini", "", "[fonts]"),
    ("GET", "/x", "f=../../proc/self/environ", "", "PATH=/usr/local/sbin"),
    ("GET", "/static/../../", "", "", "Index of"),
    (
        "POST",
        "/api",
        "",
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        "root:x:0:0",
    ),
    (
        "POST",
        "/api",
        "",
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><r>&x;</r>',
        "localhost",
    ),
    ("POST", "/api", "", '<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>', "<status>"),
    ("GET", "/ping", "host=1;id", "", "uid="),
    ("GET", "/ping", "host=1;whoami", "", "www-data"),
    ("GET", "/ping", "host=1|uname -a", "", "Linux"),
    ("GET", "/ping", "host=1;ls", "", "index"),
    ("GET", "/ping", "host=1&&ping -c 1 192.0.2.1", "", "sh"),
    ("GET", "/item", "id=1 AND SLEEP(5)", "", "MySQL"),
    ("GET", "/item", "id=1;waitfor delay '0:0:5'", "", "SQL Server"),
    ("GET", "/item", "id=1 AND pg_sleep(5)", "", "ERROR:"),
    ("GET", "/item", "id=1' OR '1'='1", "", "near '' OR '1'="),
    ("GET", "/s", "q=<script>alert(1)</script>", "", "<script>alert(1)</script>"),
    ("GET", "/", "q={{7*7}}", "", "49"),
    ("GET", "/", "q=${7*7}", "", "49"),
    ("GET", "/", "q={{7*191}}", "", "1337"),
    ("GET", "/", "q={{13*13}}", "", "169"),
    ("GET", "/", "q={{8*9}}", "", "{{8*9}}"),
    (
        "GET",
        "/fetch",
        "url=http://169.254.169.254/latest/meta-data/",
        "",
        "instance-id",
    ),
    (
        "GET",
        "/fetch",
        "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "",
        "-role",
    ),
    (
        "GET",
        "/fetch",
        "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role",
        "",
        '"AccessKeyId": "ASIA',
    ),
    (
        "GET",
        "/fetch",
        "url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "",
        '"access_token": "ya29.',
    ),
    (
        "GET",
        "/fetch",
        "url=http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "",
        '"vmId"',
    ),
    ("GET", "/.aws/credentials", "", "", "aws_access_key_id = AKIA"),
    ("GET", "/.ssh/id_rsa", "", "", "BEGIN OPENSSH PRIVATE KEY"),
    ("GET", "/.ssh/id_ed25519.pub", "", "", "ssh-ed25519 AAAA"),
    ("GET", "/.kube/config", "", "", "kind: Config"),
    ("GET", "/.docker/config.json", "", "", '"auths"'),
    ("GET", "/.npmrc", "", "", "_authToken=npm_"),
    ("GET", "/.pypirc", "", "", "password = pypi-"),
    ("GET", "/.git-credentials", "", "", "https://"),
    ("GET", "/.netrc", "", "", "machine "),
    ("GET", "/backup.sql", "", "", "INSERT INTO"),
    ("GET", "/wp-config.php.bak", "", "", "DB_PASSWORD"),
    ("GET", "/.env.production", "", "", "DB_PASSWORD="),
    ("GET", "/config.php.old", "", "", "<?php"),
    ("GET", "/actuator", "", "", '"_links"'),
    ("GET", "/actuator/env", "", "", '"propertySources"'),
    ("GET", "/phpinfo.php", "", "", "PHP Version"),
    ("GET", "/server-status", "", "", "Apache Server Status for"),
    ("GET", "/c99.php", "", "", "<form"),
    ("GET", "/shell.php", "cmd=id", "", "uid="),
    ("POST", "/shell.php", "", "cmd=whoami", "www-data"),
    # Shellshock in a body field shares the command_injection replies.
    ("GET", "/cgi-bin/test.cgi", "", "() { :; }; echo; /usr/bin/id", "uid="),
    ("GET", "/.git/config", "", "", '[remote "origin"]'),
    ("GET", "/.git/HEAD", "", "", "ref: refs/heads/"),
    ("GET", "/.svn/entries", "", "", "svn://svn.example.com"),
    ("GET", "/.vscode/sftp.json", "", "", '"protocol": "sftp"'),
    ("GET", "/.idea/workspace.xml", "", "", "DataSourceManagerImpl"),
    ("GET", "/.hg/hgrc", "", "", "404 Not Found"),
    ("GET", "/_cat/indices", "", "", "docs.count"),
    ("GET", "/_cluster/health", "", "", '"number_of_nodes"'),
    ("GET", "/users/_search", "", "", '"password_hash"'),
    ("GET", "/_nodes", "", "", "You Know, for Search"),
    ("GET", "/containers/json", "", "", '"Image"'),
    ("POST", "/containers/create", "", "", '"Warnings"'),
    ("GET", "/api/v1/namespaces/default/pods", "", "", '"PodList"'),
    ("GET", "/api/v1/namespaces", "", "", '"NamespaceList"'),
    ("GET", "/v2/_catalog", "", "", '"repositories"'),
    ("GET", "/v1.43/images/json", "", "", '"ApiVersion"'),
    (
        "POST",
        "/graphql",
        "",
        '{"query": "query IntrospectionQuery { __schema { types { name } } }"}',
        '"__schema"',
    ),
    ("GET", "/api/index.php/v1/config/application", "public=true", "", '"password"'),
    ("GET", "/WEB-INF/web.xml", "", "", "jdbc.password"),
    ("GET", "/META-INF/MANIFEST.MF", "", "", "Manifest-Version"),
    ("GET", "/v3/api-docs", "", "", '"openapi"'),
    ("GET", "/swagger-ui/index.html", "", "", "SwaggerUIBundle"),
    ("GET", "/api/users", "username[$ne]=x", "", '"users"'),
]


@pytest.mark.parametrize("method, path, query, body, marker", CASES)
def test_request_gets_matching_content(
    detector, catalog, method, path, query, body, marker
):
    reply = _answer(detector, catalog, method, path, query, body)

    assert reply is not None
    assert marker.encode() in reply.body


@pytest.mark.parametrize("method, path, query, body, marker", CASES)
def test_url_encoded_request_gets_matching_content(
    detector, catalog, method, path, query, body, marker
):
    # Clients send "/", ":" and "?" in a query percent-encoded; the selector
    # strings then match only the decoded variant.
    encoded = urllib.parse.quote(query, safe="=&")

    reply = _answer(detector, catalog, method, path, encoded, body)

    assert reply is not None
    assert marker.encode() in reply.body


def _bodies(response_type, variant):
    import yaml

    manifest = yaml.safe_load((RESPONSES / "manifest.yaml").read_text())
    patterns = manifest["responses"][response_type]["variants"][variant]["files"]
    return {
        item.read_bytes()
        for pattern in patterns
        for item in RESPONSES.glob(pattern)
        if item.is_file()
    }


@pytest.mark.parametrize(
    "response_type, variant",
    [
        ("path_traversal", "$passwd"),
        ("path_traversal", "$shadow"),
        ("xxe_injection", "$sel_passwd"),
        ("command_injection", "$sel_passwd"),
        ("cloud_metadata", "$sel_aws_creds"),
        ("cloud_metadata", "$sel_gcp"),
        ("sensitive_file", "$sel_aws"),
        ("sensitive_file", "$sel_ssh"),
        ("sensitive_file", "$sel_kube"),
        ("sensitive_file", "$sel_docker"),
        ("sensitive_file", "$sel_npmrc"),
        ("sensitive_file", "$sel_pypirc"),
        ("sensitive_file", "$sel_git_credentials"),
        ("sensitive_file", "$sel_netrc"),
        ("sensitive_file", "$sel_sql_dump"),
        ("sensitive_file", "$sel_wp_config"),
        ("sensitive_file", "$sel_dotenv"),
        ("sensitive_file", "$sel_php_config"),
        ("sensitive_file", "default"),
        ("spring_actuator", "$sel_env"),
        ("vcs_metadata", "$git_config"),
        ("vcs_metadata", "$vscode"),
        ("elasticsearch", "$search"),
        ("java_descriptor", "default"),
        ("joomla_config", "default"),
        ("nosql_result", "default"),
    ],
)
def test_secret_variants_ship_five_files(response_type, variant):
    assert len(_bodies(response_type, variant)) >= 5


def _all_bodies():
    return [item.read_bytes() for item in RESPONSES.rglob("*") if item.is_file()]


def test_fake_keys_are_not_real_keys():
    import base64

    keys = 0
    for body in _all_bodies():
        for block in re.findall(
            rb"-----BEGIN OPENSSH PRIVATE KEY-----\n(.*?)-----END", body, re.S
        ):
            keys += 1
            assert not base64.b64decode(b"".join(block.split())).startswith(
                b"openssh-key-v1\x00"
            )
        for key_id in re.findall(rb"\b(?:AKIA|ASIA)[A-Z0-9]*", body):
            assert len(key_id) == 20, key_id
    assert keys >= 5


# RFC 5737 documentation ranges and loopback.
ALLOWED_ADDRESS_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.")
NOT_ADDRESSES = {"1.0.0.1"}  # MAPIXVER in win.ini is a version number


def test_bodies_only_name_documentation_addresses():
    for body in _all_bodies():
        for address in re.findall(rb"\b\d{1,3}(?:\.\d{1,3}){3}\b", body):
            text = address.decode()
            if text not in NOT_ADDRESSES:
                assert (
                    text.startswith(ALLOWED_ADDRESS_PREFIXES)
                    or text == "169.254.169.254"
                ), text


SELECTOR_LINE = re.compile(r"^\s*\$sel_\w+\s*=.*\n", re.M)
SELECTOR_REF = " and (any of ($sel_*) or true)"


def _fired(detector):
    pairs = set()
    for index, item in enumerate(ATTACKS + BENIGN):
        for finding in detector.iter_findings(
            path=urllib.parse.unquote(item.path),
            query=item.query,
            body=item.body,
            user_agent=item.user_agent,
            method=item.method,
            headers=item.headers.items(),
        ):
            pairs.add((index, finding.rule_name))
    return pairs


def test_selector_strings_do_not_change_detection(tmp_path, detector):
    stripped = tmp_path / "rules"
    shutil.copytree(RULES, stripped)
    selectors = 0
    for item in stripped.glob("*.yar"):
        text = item.read_text()
        selectors += len(SELECTOR_LINE.findall(text))
        item.write_text(SELECTOR_LINE.sub("", text).replace(SELECTOR_REF, ""))
    without = DetectionCoordinator(YaraDetectionEngine(stripped))

    assert selectors > 0
    assert _fired(detector) == _fired(without)


def test_every_selector_rule_uses_the_neutral_reference():
    for item in RULES.glob("*.yar"):
        for name, block in re.findall(
            r"^rule\s+(\w+)\s*\{(.*?)^\}", item.read_text(), re.M | re.S
        ):
            if "$sel_" in block.split("condition:", 1)[0]:
                condition = block.split("condition:", 1)[1]
                assert SELECTOR_REF.strip() in condition, name
                assert "any of them" not in condition, name
