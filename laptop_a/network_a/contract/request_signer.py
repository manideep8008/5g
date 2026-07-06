"""HMAC request signing for the cross-network A↔B summary channel.

This module is shared crypto. Source of truth: Network A
(``network_a/contract/request_signer.py``). A byte-identical copy is vendored
into Network B (``network_b/contract/request_signer.py``) — exactly like
``identity.py``. Keep the two files identical: both cores verify each other's
signatures only when the algorithm and ``HMAC_SECRET_KEY`` match.

Wire format — four headers travel with every signed request/response::

    X-Sig-Version    signature scheme version (currently "v1")
    X-Sig-Timestamp  unix seconds (integer) when the message was signed
    X-Sig-Nonce      random per-message token (anti-replay)
    X-Sig-Value      hex HMAC-SHA256 over the canonical signing string

The signing string binds method, path and a hash of the exact body bytes, so a
signature cannot be lifted onto a different route or a tampered payload::

    version \n METHOD \n path \n timestamp \n nonce \n sha256_hex(body)

Verification is fail-closed: any missing/extra/mismatching field raises
``SignatureError``. The caller decides how to surface that (401, drop to T1…).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Mapping, MutableMapping, NamedTuple

SIGNATURE_VERSION = "v1"
DEFAULT_SKEW_SECONDS = 300

HEADER_VERSION = "X-Sig-Version"
HEADER_TIMESTAMP = "X-Sig-Timestamp"
HEADER_NONCE = "X-Sig-Nonce"
HEADER_SIGNATURE = "X-Sig-Value"

_DEFAULT_DEV_KEY = "default_dev_key_not_for_production"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


class SignatureError(Exception):
    """Raised when a signature is missing, malformed, expired or invalid."""


class VerifiedSignature(NamedTuple):
    version: str
    timestamp: int
    nonce: str


def _secret_key(key: bytes | str | None) -> bytes:
    """Resolve the HMAC key: explicit arg wins, else the shared env secret.

    Read at call time (not import) so tests and rotation see the live value.
    """
    if key is None:
        key = os.environ.get("HMAC_SECRET_KEY", _DEFAULT_DEV_KEY)
    if isinstance(key, str):
        return key.encode("utf-8")
    return key


def signing_required() -> bool:
    """Whether inbound signatures must be enforced. Defaults ON (zero-trust)."""
    return os.environ.get("REQUIRE_SIGNED_REQUESTS", "true").strip().lower() in _TRUTHY


def canonical_body(payload: Mapping) -> bytes:
    """Deterministic JSON bytes (sorted keys, no whitespace).

    Senders that build a dict payload sign over these exact bytes and put them
    on the wire, so the receiver hashes identical bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _signing_string(
    version: str, method: str, path: str, timestamp: int, nonce: str, body: bytes
) -> bytes:
    parts = [version, method.upper(), path, str(timestamp), nonce, _body_digest(body)]
    return "\n".join(parts).encode("utf-8")


def _compute(
    version: str,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body: bytes,
    key: bytes,
) -> str:
    msg = _signing_string(version, method, path, timestamp, nonce, body)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sign(
    method: str,
    path: str,
    body: bytes,
    *,
    key: bytes | str | None = None,
    timestamp: int | None = None,
    nonce: str | None = None,
    version: str = SIGNATURE_VERSION,
) -> dict[str, str]:
    """Produce the signature header dict for ``method``/``path``/``body``."""
    resolved_key = _secret_key(key)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    nce = secrets.token_hex(16) if nonce is None else nonce
    signature = _compute(version, method, path, ts, nce, body, resolved_key)
    return {
        HEADER_VERSION: version,
        HEADER_TIMESTAMP: str(ts),
        HEADER_NONCE: nce,
        HEADER_SIGNATURE: signature,
    }


class NonceCache:
    """In-memory TTL set for anti-replay. Not shared across processes."""

    def __init__(self, ttl_seconds: int = DEFAULT_SKEW_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._seen: MutableMapping[str, int] = {}

    def _prune(self, now: int) -> None:
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for n in expired:
            del self._seen[n]

    def seen_before(self, nonce: str, now: int | None = None) -> bool:
        """Record ``nonce``; return True if it was already present (a replay)."""
        current = int(time.time()) if now is None else now
        self._prune(current)
        if nonce in self._seen:
            return True
        self._seen[nonce] = current + self._ttl
        return False


def verify(
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    *,
    key: bytes | str | None = None,
    max_skew_seconds: int = DEFAULT_SKEW_SECONDS,
    nonce_cache: NonceCache | None = None,
    now: int | None = None,
) -> VerifiedSignature:
    """Verify a signature over ``body``; raise ``SignatureError`` on any fault."""
    version = headers.get(HEADER_VERSION)
    ts_raw = headers.get(HEADER_TIMESTAMP)
    nonce = headers.get(HEADER_NONCE)
    provided = headers.get(HEADER_SIGNATURE)

    if not version or not ts_raw or not nonce or not provided:
        raise SignatureError("missing signature headers")
    if version != SIGNATURE_VERSION:
        raise SignatureError(f"unsupported signature version: {version}")

    try:
        timestamp = int(ts_raw)
    except (TypeError, ValueError):
        raise SignatureError("invalid signature timestamp")

    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > max_skew_seconds:
        raise SignatureError("signature timestamp outside allowed skew")

    expected = _compute(
        version, method, path, timestamp, nonce, body, _secret_key(key)
    )
    if not hmac.compare_digest(expected, provided):
        raise SignatureError("signature mismatch")

    # Replay check happens only after the signature is proven authentic, so an
    # attacker can't poison the cache with arbitrary nonces.
    if nonce_cache is not None and nonce_cache.seen_before(nonce, now=current):
        raise SignatureError("replayed nonce")

    return VerifiedSignature(version=version, timestamp=timestamp, nonce=nonce)
