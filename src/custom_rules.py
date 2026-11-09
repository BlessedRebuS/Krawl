"""YARA rule files uploaded from the dashboard.

Uploads live in the custom_yara_rules table, so every replica loads them and
they survive restarts and read-only rules/ mounts. They are compiled together
with rules/*.yar: an upload is validated against the bundled rules, the other
uploads and the response catalogue before it is saved, then the live detector
is swapped without a restart. Other replicas pick the change up through the
reload-custom-rules task.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from datetime import datetime

import detection

logger = logging.getLogger("krawl")

MAX_RULE_FILE_BYTES = 256 * 1024
# A 64 KB body must scan in this time with every rule loaded, the same budget
# tests/test_detection_speed.py holds the bundled rules to.
MAX_SCAN_MS = 250
FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.(yar|yara)$")
# Checked on the source with comments removed; YARA also accepts `import"pe"`.
DIRECTIVE = re.compile(r'\b(import|include)\s*"')
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
SPEED_SAMPLE = (
    b"user=admin&pass=x' OR 1=1--&file=../../etc/passwd&q=<script>alert(1)</script>&"
    * 820
)[: 64 * 1024]

# Fingerprint of the uploads this process compiled. Taken from what was
# compiled, not from the table, so a file saved by another replica during an
# upload here still differs and is loaded by reload_if_changed().
_loaded_fingerprint: str | None = None
# Uploads, deletes and reloads swap the live detector one at a time.
_swap_lock = threading.Lock()


class RuleUploadError(ValueError):
    """An uploaded rule file was rejected; the message is shown to the analyst."""


# --- storage ---------------------------------------------------------------------


def _rows() -> list:
    from database import get_database
    from models import CustomYaraRule

    db = get_database()
    if not db._initialized:
        return []
    try:
        rows = db.session.query(CustomYaraRule).order_by(CustomYaraRule.filename).all()
        return [
            (row.filename, row.source, row.rule_names, row.uploaded_at) for row in rows
        ]
    finally:
        db.close_session()


def _fingerprint(sources: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for filename, source in sorted(sources.items()):
        digest.update(filename.encode())
        digest.update(hashlib.sha256(source.encode()).digest())
    return digest.hexdigest()


def _store(filename: str, source: str, rule_names: list[str]) -> None:
    from database import get_database
    from models import CustomYaraRule

    db = get_database()
    session = db.session
    try:
        row = session.get(CustomYaraRule, filename)
        if row is None:
            row = CustomYaraRule(filename=filename)
            session.add(row)
        row.source = source
        row.rule_names = ",".join(rule_names)
        row.uploaded_at = datetime.now()
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        db.close_session()


def stored_sources() -> dict[str, str]:
    return {filename: source for filename, source, _, _ in _rows()}


def list_files() -> list[dict]:
    """Uploaded files for the dashboard, by file name."""
    return [
        {
            "filename": filename,
            "rules": [name for name in names.split(",") if name],
            "uploaded_at": uploaded_at,
            "size": len(source.encode("utf-8")),
        }
        for filename, source, names, uploaded_at in _rows()
    ]


def get_source(filename: str) -> str | None:
    return stored_sources().get(filename)


# --- loading -----------------------------------------------------------------------


def loadable_sources(config) -> dict[str, str]:
    """Stored uploads that compile with the current bundled rules.

    A file that stopped compiling (a rule name now bundled, a removed response
    type) is logged and skipped, so it can never stop Krawl from starting.
    """
    global _loaded_fingerprint
    try:
        sources = stored_sources()
    except Exception as exc:
        # The bundled rules still load; the reload task retries every 30 s.
        logger.error(f"Could not read uploaded YARA rule files: {exc}")
        return {}
    _loaded_fingerprint = _fingerprint(sources)
    if not sources:
        return {}
    try:
        detection.build_detection(config, sources)
        return sources
    except Exception:  # noqa: S110 - find the culprits below
        pass
    good: dict[str, str] = {}
    for filename, source in sources.items():
        try:
            detection.build_detection(config, {**good, filename: source})
            good[filename] = source
        except Exception as exc:
            logger.error(f"Skipping uploaded YARA rule file {filename}: {exc}")
    return good


def reload_if_changed() -> bool:
    """Reload when another replica uploaded or deleted a file. True if reloaded."""
    if _fingerprint(stored_sources()) == _loaded_fingerprint:
        return False
    from config import get_config

    with _swap_lock:
        detection.initialize_detection(get_config())
    logger.info("[Rules] Reloaded uploaded YARA rules changed on another replica")
    return True


# --- upload and delete ---------------------------------------------------------------


def _check_source(filename: str, source: str) -> None:
    if not FILENAME.fullmatch(filename or ""):
        raise RuleUploadError(
            "Invalid file name: use letters, digits, _ and -, ending in .yar or .yara"
        )
    if not source.strip():
        raise RuleUploadError("The rule file is empty")
    if len(source.encode("utf-8")) > MAX_RULE_FILE_BYTES:
        raise RuleUploadError("The rule file is larger than 256 KB")
    if DIRECTIVE.search(COMMENT.sub(" ", source)):
        raise RuleUploadError(
            "import and include statements are not allowed in uploaded rules"
        )


def _compile_alone(filename: str, source: str) -> None:
    """Report syntax errors with line numbers of the uploaded file itself."""
    import yara

    try:
        yara.compile(
            source=source,
            externals={"scan_target": "", "http_method": "", "header_name": ""},
            includes=False,
            error_on_warning=True,
            strict_escape=True,
        )
    except yara.Error as exc:
        raise RuleUploadError(f"{filename}: {exc}") from exc


def _uploaded_rule_names(coordinator, filename: str) -> list[str]:
    rule_file = "uploaded/" + filename.rsplit(".", 1)[0]
    return [
        row["rule"]
        for row in coordinator.list_rules()
        if row["uploaded"] and row["rule_file"] == rule_file
    ]


def _check_speed(coordinator) -> None:
    started = time.perf_counter()
    coordinator.yara.rules.match(
        data=SPEED_SAMPLE,
        externals={"scan_target": "body", "http_method": "POST", "header_name": ""},
    )
    elapsed = (time.perf_counter() - started) * 1000
    if elapsed > MAX_SCAN_MS:
        raise RuleUploadError(
            f"The rules are too slow: a 64 KB body took {elapsed:.0f} ms to scan "
            f"(limit {MAX_SCAN_MS} ms). Start each regular expression with a "
            "literal of two or more bytes."
        )


def upload(filename: str, source: str) -> list[str]:
    """Validate, store and load a rule file; replaces a file with the same name.

    Returns the rule names it defines. Raises RuleUploadError, leaving the
    stored files and the live detector unchanged, when it is not valid.
    """
    _check_source(filename, source)
    _compile_alone(filename, source)
    with _swap_lock:
        return _upload_locked(filename, source)


def _upload_locked(filename: str, source: str) -> list[str]:
    global _loaded_fingerprint
    from config import get_config

    others = {name: text for name, text in stored_sources().items() if name != filename}
    stem = filename.rsplit(".", 1)[0]
    clash = next((name for name in others if name.rsplit(".", 1)[0] == stem), None)
    if clash:
        raise RuleUploadError(
            f"{clash} is already uploaded; upload the new file as {clash} to "
            "replace it, or delete it first"
        )
    compiled = {**others, filename: source}
    try:
        coordinator, catalog = detection.build_detection(get_config(), compiled)
    except RuntimeError as exc:
        raise RuleUploadError(str(exc)) from exc
    names = _uploaded_rule_names(coordinator, filename)
    if not names:
        raise RuleUploadError("The rule file contains no rules")
    _check_speed(coordinator)

    _store(filename, source, names)
    detection.set_detection(coordinator, catalog)
    _loaded_fingerprint = _fingerprint(compiled)
    logger.info(f"[Rules] Uploaded {filename}: {', '.join(names)}")
    return names


def delete(filename: str) -> bool:
    """Remove an uploaded file and its rules. False when there is no such file."""
    from config import get_config
    from database import get_database
    from models import CustomYaraRule

    with _swap_lock:
        db = get_database()
        session = db.session
        try:
            row = session.get(CustomYaraRule, filename)
            if row is None:
                return False
            session.delete(row)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            db.close_session()
        detection.initialize_detection(get_config())
    logger.info(f"[Rules] Deleted uploaded rule file {filename}")
    return True
