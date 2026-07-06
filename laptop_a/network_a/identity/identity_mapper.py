
from __future__ import annotations

import hashlib
import hmac
import os

from network_a import db

_HMAC_KEY = os.environ.get("HMAC_SECRET_KEY", "default_dev_key_not_for_production").encode("utf-8")


def pseudonymise_imsi(imsi: str) -> str:
    digest = hmac.new(_HMAC_KEY, imsi.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"UE_HASH_{digest[:12].upper()}"


def verify_pseudonym(imsi: str, pseudonym: str) -> bool:
    return pseudonymise_imsi(imsi) == pseudonym


async def get_or_create_pseudonym(imsi: str, network_b_id: str = "Network_B") -> str:
    pseudonym = pseudonymise_imsi(imsi)
    imsi_hmac = pseudonym
    await db.insert_identity(pseudonym, imsi_hmac, network_b_id)
    return pseudonym


async def lookup_pseudonym(pseudonym: str) -> dict | None:
    return await db.get_identity(pseudonym)


def get_pseudonym_sync(imsi: str) -> str:
    return pseudonymise_imsi(imsi)