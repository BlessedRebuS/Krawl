#!/usr/bin/env python3

"""
TLSH fuzzy-hash helpers for near-duplicate payload clustering.

Wraps the optional `tlsh` (py-tlsh) C extension with safe guards:
py-tlsh returns "TNULL" when input is too short or lacks entropy, and throws
on some operations against such input. All callers must tolerate a None result.

The module imports lazily so Krawl still boots when the C extension is absent
(only the clustering feature degrades).
"""

import hashlib
import logging
import re
from email import policy
from email.parser import Parser

logger = logging.getLogger("krawl")

try:  # pragma: no cover - exercised only when the C extension is installed
    import tlsh as _tlsh
except Exception:  # pragma: no cover
    _tlsh = None

_MIN_TLSH_INPUT = 50

# Similarity threshold for tlsh.diff(): 0 = identical, higher = more different.
# 200 is the recommended "different" cutoff; variants of the same payload are
# typically < 100.
SIMILARITY_THRESHOLD = 150


def tlsh_available() -> bool:
    """True if the TLSH C extension is importable."""
    return _tlsh is not None


def tlsh_hash(data: bytes) -> str | None:
    """Return the TLSH digest for bytes, or None if unsupported/too small.

    TLSH needs >= ~50 bytes with enough entropy; uniform/near-uniform data
    produces TNULL which we map to None (meaning "not clusterable").
    """
    if _tlsh is None or not data or len(data) < _MIN_TLSH_INPUT:
        return None
    try:
        digest = _tlsh.hash(data)
    except Exception as e:
        logger.debug(f"TLSH hash failed: {e}")
        return None
    if not digest or digest == "TNULL":
        return None
    return digest


def sha256_hash(data: bytes) -> str:
    """Exact SHA-256 of the payload, complementing the fuzzy TLSH digest."""
    return hashlib.sha256(data).hexdigest()


def tlsh_diff(h1: str | None, h2: str | None) -> int | None:
    """TLSH distance (0 = identical, higher = more different), or None if
    either digest is unavailable/invalid. Similarity checkers should compare
    the result against SIMILARITY_THRESHOLD."""
    if _tlsh is None or not h1 or not h2:
        return None
    try:
        return _tlsh.diff(h1, h2)
    except Exception:
        return None


def is_similar(h1: str | None, h2: str | None, threshold: int = SIMILARITY_THRESHOLD) -> bool:
    """True if two TLSH digests are within the similarity threshold."""
    d = tlsh_diff(h1, h2)
    return d is not None and d <= threshold


_FILE_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-php",
    "application/x-sh",
    "application/x-httpd-php",
    "text/php",
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/pdf",
    "application/msword",
}


def _is_file_content_type(content_type: str) -> bool:
    ct = (content_type or "").lower().split(";")[0].strip()
    return ct in _FILE_CONTENT_TYPES or any(
        ct.startswith(p)
        for p in ("image/", "audio/", "video/", "font/", "application/x-ms")
    )


def extract_file_payloads(raw_request: str, max_files: int = 8) -> list[dict]:
    """Parse file uploads out of a raw HTTP request.

    Returns a list of {filename, content_type, size, content, tlsh_hash, sha256}.
    Content is retained (it is what TLSH hashes); callers decide what to index.
    Bytes are used only for hashing — the raw_request column already stores the
    full body for forensic use.
    """
    if not raw_request:
        return []
    try:
        header_end = raw_request.find("\r\n\r\n")
        if header_end < 0:
            return []
        headers_text = raw_request[:header_end]
        body = raw_request[header_end + 4 :]
        if not body:
            return []

        ct_match = re.search(r"[Cc]ontent-[Tt]ype:\s*([^\r\n]+)", headers_text)
        content_type = ct_match.group(1) if ct_match else ""

        results: list[dict] = []
        if content_type.startswith("multipart/form-data"):
            b_match = re.search(r"boundary=([^\s;]+)", content_type)
            if not b_match:
                return []
            if not body.endswith("\r\n"):
                body += "\r\n"
            msg = Parser(policy=policy.compat32).parsestr(
                f"Content-Type: {content_type}\r\n\r\n{body}"
            )
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                disp = part.get("Content-Disposition", "")
                has_file = "attachment" in disp or part.get_filename()
                if not has_file:
                    continue
                filename = part.get_filename() or ""
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b""
                results.append(
                    {
                        "filename": filename,
                        "content_type": part.get_content_type()
                        or "application/octet-stream",
                        "size": len(payload),
                        "content": payload,
                        "tlsh_hash": tlsh_hash(payload),
                        "sha256": sha256_hash(payload),
                    }
                )
                if len(results) >= max_files:
                    break
        elif _is_file_content_type(content_type):
            payload = body.encode("utf-8", errors="replace")
            results.append(
                {
                    "filename": "",
                    "content_type": content_type.split(";")[0].strip(),
                    "size": len(payload),
                    "content": payload,
                    "tlsh_hash": tlsh_hash(payload),
                    "sha256": sha256_hash(payload),
                }
            )
        # Drop unhashable/oversized content after hashing; only metadata persists.
        for r in results:
            r["content"] = None
        return results
    except Exception as e:
        logger.debug(f"extract_file_payloads failed: {e}")
        return []
