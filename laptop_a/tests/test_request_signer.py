"""Tests for the HMAC request-signing layer (Network A source of truth).

The same suite is vendored into Network B; both must stay byte-identical so
the two cores verify each other's signatures. See the parity test at the end.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from network_a.contract import request_signer as rs

_A_SOURCE = Path(__file__).resolve().parents[1] / "network_a" / "contract" / "request_signer.py"
_B_COPY = (
    Path(__file__).resolve().parents[2]
    / "laptop_b"
    / "network_b"
    / "contract"
    / "request_signer.py"
)

KEY = b"unit-test-secret-key"
METHOD = "POST"
PATH = "/v1/summary/request"
BODY = b'{"hello":"world"}'


# ── canonical_body ────────────────────────────────────────────────


@pytest.mark.unit
def test_canonical_body_is_deterministic_regardless_of_key_order() -> None:
    a = rs.canonical_body({"b": 2, "a": 1})
    b = rs.canonical_body({"a": 1, "b": 2})
    assert a == b
    assert a == b'{"a":1,"b":2}'


# ── sign / verify roundtrip ───────────────────────────────────────


@pytest.mark.unit
def test_sign_then_verify_roundtrip() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    assert headers[rs.HEADER_VERSION] == rs.SIGNATURE_VERSION
    assert headers[rs.HEADER_TIMESTAMP]
    assert headers[rs.HEADER_NONCE]
    assert headers[rs.HEADER_SIGNATURE]

    verified = rs.verify(METHOD, PATH, BODY, headers, key=KEY)
    assert verified.nonce == headers[rs.HEADER_NONCE]


@pytest.mark.unit
def test_verify_uses_env_secret_when_no_key_passed(monkeypatch) -> None:
    monkeypatch.setenv("HMAC_SECRET_KEY", "env-driven-secret")
    headers = rs.sign(METHOD, PATH, BODY)
    # No key arg → both sides fall back to the shared env secret.
    rs.verify(METHOD, PATH, BODY, headers)


# ── tamper / wrong key / wrong route ──────────────────────────────


@pytest.mark.unit
def test_tampered_body_is_rejected() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY + b"x", headers, key=KEY)


@pytest.mark.unit
def test_wrong_key_is_rejected() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=b"different-key")


@pytest.mark.unit
def test_wrong_method_or_path_is_rejected() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    with pytest.raises(rs.SignatureError):
        rs.verify("GET", PATH, BODY, headers, key=KEY)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, "/v1/other", BODY, headers, key=KEY)


# ── skew window ───────────────────────────────────────────────────


@pytest.mark.unit
def test_expired_timestamp_is_rejected() -> None:
    old = int(time.time()) - 10_000
    headers = rs.sign(METHOD, PATH, BODY, key=KEY, timestamp=old)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY, max_skew_seconds=300)


@pytest.mark.unit
def test_future_timestamp_beyond_skew_is_rejected() -> None:
    future = int(time.time()) + 10_000
    headers = rs.sign(METHOD, PATH, BODY, key=KEY, timestamp=future)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY, max_skew_seconds=300)


# ── missing / malformed headers ───────────────────────────────────


@pytest.mark.unit
@pytest.mark.parametrize(
    "drop",
    [rs.HEADER_VERSION, rs.HEADER_TIMESTAMP, rs.HEADER_NONCE, rs.HEADER_SIGNATURE],
)
def test_missing_header_is_rejected(drop: str) -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    del headers[drop]
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY)


@pytest.mark.unit
def test_unknown_version_is_rejected() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    headers[rs.HEADER_VERSION] = "v999"
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY)


@pytest.mark.unit
def test_non_integer_timestamp_is_rejected() -> None:
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    headers[rs.HEADER_TIMESTAMP] = "not-a-number"
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY)


# ── replay protection ─────────────────────────────────────────────


@pytest.mark.unit
def test_replayed_nonce_is_rejected() -> None:
    cache = rs.NonceCache(ttl_seconds=300)
    headers = rs.sign(METHOD, PATH, BODY, key=KEY)
    rs.verify(METHOD, PATH, BODY, headers, key=KEY, nonce_cache=cache)
    with pytest.raises(rs.SignatureError):
        rs.verify(METHOD, PATH, BODY, headers, key=KEY, nonce_cache=cache)


@pytest.mark.unit
def test_nonce_cache_expires_entries() -> None:
    cache = rs.NonceCache(ttl_seconds=1)
    now = 1_000_000
    assert cache.seen_before("abc", now=now) is False
    assert cache.seen_before("abc", now=now) is True
    # After TTL, the same nonce is forgotten.
    assert cache.seen_before("abc", now=now + 5) is False


# ── config toggle ─────────────────────────────────────────────────


@pytest.mark.unit
def test_signing_required_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv("REQUIRE_SIGNED_REQUESTS", raising=False)
    assert rs.signing_required() is True


@pytest.mark.unit
@pytest.mark.parametrize("val", ["0", "false", "no", "off", "FALSE"])
def test_signing_required_can_be_disabled(monkeypatch, val: str) -> None:
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", val)
    assert rs.signing_required() is False


# ── vendoring parity (source of truth ↔ Network B copy) ───────────


@pytest.mark.unit
def test_network_b_copy_is_byte_identical() -> None:
    if not _B_COPY.exists():
        pytest.skip("Network B copy not present in this checkout")
    assert _A_SOURCE.read_bytes() == _B_COPY.read_bytes(), (
        "request_signer.py drifted between Network A (source) and Network B "
        "(vendored copy); re-copy A's file into B to keep signatures compatible."
    )
