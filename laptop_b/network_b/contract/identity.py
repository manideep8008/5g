"""Identity pseudonymisation — pure HMAC, no database.

Vendored into Network B's standalone deployment by scripts/export_standalone.py.
Source of truth: network_a/identity/identity_mapper.py. The DB-backed helpers
are intentionally omitted — Network B only needs the pure derivation.

The HMAC derivation MUST stay byte-identical to Network A: both cores agree
"this is the same UE" only when HMAC_SECRET_KEY and this algorithm match.
"""
from __future__ import annotations

import hashlib
import hmac
import os

_HMAC_KEY = os.environ.get(
    "HMAC_SECRET_KEY", "default_dev_key_not_for_production"
).encode("utf-8")


def pseudonymise_imsi(imsi: str) -> str:
    digest = hmac.new(_HMAC_KEY, imsi.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"UE_HASH_{digest[:12].upper()}"


def verify_pseudonym(imsi: str, pseudonym: str) -> bool:
    return pseudonymise_imsi(imsi) == pseudonym


def get_pseudonym_sync(imsi: str) -> str:
    return pseudonymise_imsi(imsi)
