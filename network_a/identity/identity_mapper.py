"""
Identity mapper — maps IMSI to pseudonym via HMAC, backed by Postgres.

Falls back to in-memory when Postgres is unavailable (same as db.py).
"""
from __future__ import annotations

from network_a.identity.ue_hasher import pseudonymise_imsi
from network_a import db


async def get_or_create_pseudonym(imsi: str, network_b_id: str = "Network_B") -> str:
    pseudonym = pseudonymise_imsi(imsi)
    imsi_hmac = pseudonym
    await db.insert_identity(pseudonym, imsi_hmac, network_b_id)
    return pseudonym


async def lookup_pseudonym(pseudonym: str) -> dict | None:
    return await db.get_identity(pseudonym)


def get_pseudonym_sync(imsi: str) -> str:
    return pseudonymise_imsi(imsi)
