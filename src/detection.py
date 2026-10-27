"""Request attack detection with YARA rules."""

from __future__ import annotations

import logging
import re
import urllib.parse
from collections.abc import Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Literal

logger = logging.getLogger("krawl")

ScanTarget = Literal["path", "query", "body", "user_agent", "header"]

MAX_SCANNED_HEADERS = 64
MAX_HEADER_VALUE_BYTES = 8 * 1024


@dataclass(frozen=True)
class DetectionFinding:
    attack_type: str
    matched_pattern: str
    source: Literal["yara", "credential_fields"]
    scan_target: ScanTarget
    classification: Literal["attack", "suspicious"] = "attack"
    severity: int = 1
    rule_name: str = ""
    namespace: str = ""
    response_type: str = ""
    offset: int = 0
    # Identifiers of every string the rule matched ("$passwd"), first offset first.
    pattern_ids: tuple[str, ...] = ()


MITRE_ID = re.compile(r"T\d{4}(\.\d{3})?")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
MAX_ATTACK_TYPE_LENGTH = 50  # AttackDetection.attack_type is String(50)


def _split_list(value) -> list[str]:
    return [item.strip() for item in str(value).split(",")]


def _is_date(value) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except (TypeError, ValueError):
        return False
    return len(value) == 10


def _rule_details(name: str, rule_file: str, meta: dict) -> dict:
    """The metadata an analyst needs to judge a match, with lists split."""

    def as_list(field: str) -> list[str]:
        return [item for item in _split_list(meta.get(field, "")) if item]

    return {
        "rule": name,
        "rule_file": rule_file,
        "attack_type": str(meta["attack_type"]),
        "classification": str(meta["classification"]),
        "severity": int(meta["severity"]),
        "confidence": str(meta.get("confidence", "")),
        "description": str(meta.get("description", "")),
        "mitre_attack": as_list("mitre_attack"),
        "cve": as_list("cve"),
        # Rendered as links on the dashboard, so only web URLs are kept.
        "references": [
            ref
            for ref in as_list("reference")
            if ref.startswith(("https://", "http://"))
        ],
        "false_positives": str(meta.get("false_positives", "")),
    }


def _validate_rule_meta(
    name: str, meta: dict, known_response_types: Collection[str] | None = None
) -> None:
    def fail(field: str, problem: str):
        raise RuntimeError(f"YARA rule {name} has invalid {field}: {problem}")

    attack_type = meta["attack_type"]
    if not isinstance(attack_type, str) or not attack_type:
        fail("attack_type", "must be a non-empty string")
    if len(attack_type) > MAX_ATTACK_TYPE_LENGTH:
        fail("attack_type", f"longer than {MAX_ATTACK_TYPE_LENGTH} characters")
    if meta["classification"] not in {"attack", "suspicious"}:
        raise RuntimeError(
            f"YARA rule {name} has invalid classification {meta['classification']!r}"
        )
    severity = meta["severity"]
    if not isinstance(severity, int) or isinstance(severity, bool):
        raise RuntimeError(f"YARA rule {name} has non-integer severity {severity!r}")
    if not 1 <= severity <= 10:
        fail("severity", f"{severity} is outside 1-10")

    if "confidence" in meta and meta["confidence"] not in {"high", "medium", "low"}:
        fail("confidence", f"{meta['confidence']!r} (expected high, medium or low)")
    if "mitre_attack" in meta and not all(
        MITRE_ID.fullmatch(item) for item in _split_list(meta["mitre_attack"])
    ):
        fail("mitre_attack", f"{meta['mitre_attack']!r} (expected T1234 or T1234.567)")
    if "cve" in meta and not all(
        CVE_ID.fullmatch(item) for item in _split_list(meta["cve"])
    ):
        fail("cve", f"{meta['cve']!r} (expected CVE-YYYY-NNNN)")
    for field in ("date", "modified"):
        if field in meta and not _is_date(meta[field]):
            fail(field, f"{meta[field]!r} (expected YYYY-MM-DD)")
    if (
        known_response_types is not None
        and "response_type" in meta
        and meta["response_type"] not in known_response_types
    ):
        fail(
            "response_type",
            f"{meta['response_type']!r} (known: {', '.join(sorted(known_response_types))})",
        )


RULE_BLOCK = re.compile(r"^rule\s+(\w+)\s*\{(.*?)^\}", re.M | re.S)
STRING_LINE = re.compile(r"^\s*(\$\w*)\s*=", re.M)


def _rule_files(rules_path: str | Path) -> list[Path]:
    path = Path(rules_path)
    return sorted((*path.glob("*.yar"), *path.glob("*.yara")))


def declared_string_ids(
    rules_path: str | Path, uploaded: Mapping[str, str] | None = None
) -> dict[str, frozenset[str]]:
    """Rule name -> its string identifiers, parsed from the .yar sources.

    yara-python does not expose identifiers on compiled rules.
    """
    texts = [item.read_text(encoding="utf-8") for item in _rule_files(rules_path)]
    texts += list((uploaded or {}).values())
    declared = {}
    for text in texts:
        for name, block in RULE_BLOCK.findall(text):
            strings = block.split("strings:", 1)[-1].split("condition:", 1)[0]
            declared[name] = frozenset(STRING_LINE.findall(strings))
    return declared


class YaraDetectionEngine:
    REQUIRED_META = {"attack_type", "classification", "severity"}

    def __init__(
        self,
        rules_path: str | Path,
        known_response_types: Collection[str] | None = None,
        uploaded: Mapping[str, str] | None = None,
    ):
        """Compile rules/*.yar plus `uploaded` (file name -> source), the rule
        files analysts added from the dashboard."""
        try:
            import yara
        except ImportError as exc:  # pragma: no cover - depends on deployment image
            raise RuntimeError("yara-python is required for YARA detection") from exc

        self._yara = yara
        path = Path(rules_path)
        files = _rule_files(path)
        if not files:
            raise RuntimeError(f"No YARA rules found in {path}")
        sources = {
            f"krawl_{index}_{item.stem}": item.read_text(encoding="utf-8")
            for index, item in enumerate(files)
        }
        self._rule_files = {
            f"krawl_{index}_{item.stem}": item.stem for index, item in enumerate(files)
        }
        for index, (filename, source) in enumerate(sorted((uploaded or {}).items())):
            stem = Path(filename).stem
            sources[f"uploaded_{index}_{stem}"] = source
            self._rule_files[f"uploaded_{index}_{stem}"] = f"uploaded/{stem}"
        # attack_type -> details of every rule that reports it, for analysts.
        self.rule_details: dict[str, list[dict]] = {}
        self.rule_strings = declared_string_ids(path, uploaded)
        self.rule_response_types: dict[str, str] = {}
        self._known_response_types = known_response_types
        try:
            self.rules = yara.compile(
                sources=sources,
                externals={"scan_target": "", "http_method": "", "header_name": ""},
                includes=False,
                error_on_warning=True,
                strict_escape=True,
            )
        except yara.Error as exc:
            raise RuntimeError(
                f"Could not compile YARA rules from {path}: {exc}"
            ) from exc
        self._validate_metadata()

    def _validate_metadata(self) -> None:
        names: set[str] = set()

        def validate(rule):
            name = rule.get("rule", "<unknown>")
            if name in names:
                raise RuntimeError(f"YARA rule name {name} is defined more than once")
            names.add(name)
            meta = rule.get("meta", {})
            missing = self.REQUIRED_META - set(meta)
            if missing:
                raise RuntimeError(
                    f"YARA rule {name} is missing metadata: {', '.join(sorted(missing))}"
                )
            _validate_rule_meta(name, meta, self._known_response_types)
            if meta.get("response_type"):
                self.rule_response_types[name] = str(meta["response_type"])
            namespace = rule.get("namespace", "")
            details = _rule_details(name, self._rule_files.get(namespace, ""), meta)
            details["uploaded"] = namespace.startswith("uploaded_")
            self.rule_details.setdefault(details["attack_type"], []).append(details)
            return self._yara.CALLBACK_CONTINUE

        self.rules.match(
            data=b"",
            callback=validate,
            which_callbacks=self._yara.CALLBACK_ALL,
            externals={
                "scan_target": "metadata_validation",
                "http_method": "GET",
                "header_name": "",
            },
        )
        if not names:
            raise RuntimeError("The YARA ruleset contains no rules")

    def scan_field(
        self, data: str, target: ScanTarget, method: str = "GET", header_name: str = ""
    ) -> list[DetectionFinding]:
        if not data:
            return []
        try:
            matches = self.rules.match(
                data=data.encode("utf-8", errors="replace"),
                externals={
                    "scan_target": target,
                    "http_method": method.upper(),
                    "header_name": header_name,
                },
            )
        except self._yara.Error as exc:
            logger.error("YARA scan failed for %s: %s", target, exc)
            return []

        findings = []
        for match in matches:
            evidence = ""
            offset = 0
            instances = [
                instance
                for string_match in match.strings
                for instance in string_match.instances
            ]
            first_offsets = {
                string_match.identifier: min(i.offset for i in string_match.instances)
                for string_match in match.strings
                if string_match.instances
            }
            pattern_ids = tuple(sorted(first_offsets, key=first_offsets.get))
            if instances:
                instance = min(instances, key=lambda item: item.offset)
                offset = instance.offset
                evidence = bytes(instance.matched_data).decode(
                    "utf-8", errors="replace"
                )[:256]
            meta = match.meta
            findings.append(
                DetectionFinding(
                    attack_type=str(meta["attack_type"]),
                    matched_pattern=evidence,
                    source="yara",
                    scan_target=target,
                    classification=str(meta["classification"]),
                    severity=int(meta["severity"]),
                    rule_name=match.rule,
                    namespace=match.namespace,
                    response_type=str(meta.get("response_type", "")),
                    offset=offset,
                    pattern_ids=pattern_ids,
                )
            )
        return findings


class DetectionCoordinator:
    """Runs the YARA engine over every field of a request."""

    def __init__(self, yara_engine: YaraDetectionEngine):
        self.yara = yara_engine
        self.engine = yara_engine

    @staticmethod
    def _variants(value: str, decode_count: int, form: bool = False) -> list[str]:
        # Query strings and form bodies encode spaces as "+".
        unquote = urllib.parse.unquote_plus if form else urllib.parse.unquote
        values = [value]
        current = value
        for _ in range(decode_count):
            current = unquote(current)
            if current not in values:
                values.append(current)
        return values

    def _header_fields(self, headers) -> Iterator[tuple[str, list[str]]]:
        for index, (name, value) in enumerate(headers):
            if index >= MAX_SCANNED_HEADERS:
                logger.debug("Header scan stopped after %d headers", index)
                break
            name = name.lower()
            if name == "user-agent":  # scanned as its own target
                continue
            if len(value) > MAX_HEADER_VALUE_BYTES:
                logger.debug("Skipping oversized header %s (%d)", name, len(value))
                continue
            yield name, self._variants(value, 1)

    def scan_inputs(
        self,
        *,
        path: str = "",
        query: str = "",
        body: str = "",
        user_agent: str = "",
        headers: Iterable[tuple[str, str]] | None = None,
    ) -> Iterator[tuple[ScanTarget, str, str]]:
        """Yield (target, header_name, value) for every variant that is scanned."""
        fields = [
            ("path", "", self._variants(path, 2)),
            ("query", "", self._variants(query, 2, form=True)),
            ("body", "", self._variants(body, 1, form=True)),
            ("user_agent", "", [user_agent]),
        ]
        fields += [
            ("header", name, values)
            for name, values in self._header_fields(headers or ())
        ]
        for target, header_name, values in fields:
            for value in values:
                yield target, header_name, value

    def iter_findings(
        self,
        *,
        path: str = "",
        query: str = "",
        body: str = "",
        user_agent: str = "",
        method: str = "GET",
        headers: Iterable[tuple[str, str]] | None = None,
    ) -> Iterator[DetectionFinding]:
        """Yield every raw finding, including lower-severity duplicates."""
        for target, header_name, value in self.scan_inputs(
            path=path, query=query, body=body, user_agent=user_agent, headers=headers
        ):
            yield from self.engine.scan_field(value, target, method, header_name)

    def scan_request(
        self,
        *,
        path: str = "",
        query: str = "",
        body: str = "",
        user_agent: str = "",
        method: str = "GET",
        headers: Iterable[tuple[str, str]] | None = None,
    ) -> list[DetectionFinding]:
        """Return one finding per attack type, highest severity first.

        Each finding's `pattern_ids` holds the string ids matched by every
        finding of its type, so ids seen only in a decoded variant still pick a
        response variant.
        """
        selected: dict[str, DetectionFinding] = {}
        pattern_ids: dict[str, dict[str, None]] = {}
        for finding in self.iter_findings(
            path=path,
            query=query,
            body=body,
            user_agent=user_agent,
            method=method,
            headers=headers,
        ):
            previous = selected.get(finding.attack_type)
            if previous is None or finding.severity > previous.severity:
                selected[finding.attack_type] = finding
            # A dict keeps first-seen order without duplicates.
            pattern_ids.setdefault(finding.attack_type, {}).update(
                dict.fromkeys(finding.pattern_ids)
            )
        merged = [
            replace(finding, pattern_ids=tuple(pattern_ids[attack_type]))
            for attack_type, finding in selected.items()
        ]
        return sorted(merged, key=lambda item: (-item.severity, item.attack_type))

    def list_rules(self) -> list[dict]:
        """Every loaded rule's details plus its response_type ("" when none)."""
        response_types = self.yara.rule_response_types
        return sorted(
            (
                {**details, "response_type": response_types.get(details["rule"], "")}
                for rules in self.yara.rule_details.values()
                for details in rules
            ),
            key=lambda item: item["rule"],
        )

    def describe_attack_types(self, attack_types) -> dict[str, list[dict]]:
        """Map each attack type to the details of the YARA rules that report it."""
        details = self.yara.rule_details
        return {
            attack_type: sorted(
                details.get(attack_type, []),
                key=lambda item: (-item["severity"], item["rule"]),
            )
            for attack_type in attack_types
        }

    def scan_value(
        self,
        data: str,
        *,
        target: ScanTarget = "path",
        method: str = "GET",
        exclude: set[str] | None = None,
    ) -> list[DetectionFinding]:
        kwargs = {"path": "", "query": "", "body": "", "user_agent": ""}
        kwargs[target] = data
        findings = self.scan_request(method=method, **kwargs)
        return [
            item for item in findings if not exclude or item.attack_type not in exclude
        ]


_coordinator: DetectionCoordinator | None = None
_catalog = None  # responses.ResponseCatalog, set by initialize_detection

PROJECT_ROOT = Path(__file__).parent.parent


def _project_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def build_detection(config, uploaded: Mapping[str, str] | None = None):
    """Compile a detector and its response catalogue; raise on any mismatch.

    Returns (DetectionCoordinator, ResponseCatalog) without installing them.
    """
    from responses import ResponseCatalog

    catalog = ResponseCatalog.load(_project_path(config.responses_path))
    yara_engine = YaraDetectionEngine(
        _project_path(config.yara_rules_path),
        known_response_types=catalog.response_types,
        uploaded=uploaded,
    )
    catalog.check_rules(yara_engine.rule_response_types, yara_engine.rule_strings)
    return DetectionCoordinator(yara_engine), catalog


def set_detection(coordinator: DetectionCoordinator, catalog) -> None:
    """Swap the live detector; requests in flight keep the one they started with."""
    global _coordinator, _catalog
    _catalog = catalog
    _coordinator = coordinator


def initialize_detection(config, uploaded=None) -> DetectionCoordinator:
    """Load the bundled rules, the uploaded ones and the response catalogue.

    The bundled set must be valid or Krawl does not start. An uploaded file
    that no longer compiles against it is logged and skipped.
    """
    if uploaded is None:
        import custom_rules

        uploaded = custom_rules.loadable_sources(config)
    coordinator, catalog = build_detection(config, uploaded)
    set_detection(coordinator, catalog)
    return coordinator


def get_detection() -> DetectionCoordinator:
    global _coordinator
    if _coordinator is None:
        from config import get_config

        _coordinator = initialize_detection(get_config())
    return _coordinator


def get_response_catalog():
    """The deception response catalogue loaded at startup."""
    if _catalog is None:
        from config import get_config

        initialize_detection(get_config())
    return _catalog
