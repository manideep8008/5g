"""Tests for the database layer using in-memory fallback."""

import pytest
from datetime import datetime, timezone

from network_a import db


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


@pytest.mark.asyncio
async def test_insert_and_get_identity():
    await db.insert_identity("UE_HASH_TEST", "hmac_test", "Network_B")
    result = await db.get_identity("UE_HASH_TEST")
    assert result is not None
    assert result["pseudonym"] == "UE_HASH_TEST"
    assert result["network_b_id"] == "Network_B"


@pytest.mark.asyncio
async def test_insert_identity_idempotent():
    await db.insert_identity("UE_HASH_TEST", "hmac_test", "Network_B")
    await db.insert_identity("UE_HASH_TEST", "hmac_test", "Network_B")
    count = sum(1 for r in db._MEMORY_STORE["ue_identity"] if r["pseudonym"] == "UE_HASH_TEST")
    assert count == 1


@pytest.mark.asyncio
async def test_get_identity_not_found():
    result = await db.get_identity("NONEXISTENT")
    assert result is None


@pytest.mark.asyncio
async def test_insert_and_get_session():
    await db.insert_identity("UE_HASH_TEST", "hmac_test")
    session_id = await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        registration_success=True,
        auth_attempts=1,
        auth_failures=0,
        pdu_attempts=1,
        pdu_failures=0,
    )
    assert session_id == 1

    sessions = await db.get_sessions_for_ue("UE_HASH_TEST")
    assert len(sessions) == 1
    assert sessions[0]["registration_success"] is True


@pytest.mark.asyncio
async def test_multiple_sessions():
    await db.insert_identity("UE_HASH_TEST", "hmac_test")
    for i in range(5):
        await db.insert_session(
            pseudonym="UE_HASH_TEST",
            started_at=datetime.now(timezone.utc),
            registration_success=True,
        )
    sessions = await db.get_sessions_for_ue("UE_HASH_TEST")
    assert len(sessions) == 5


@pytest.mark.asyncio
async def test_insert_and_get_risk_flags():
    await db.insert_identity("UE_HASH_TEST", "hmac_test")
    await db.insert_risk_flag("UE_HASH_TEST", "auth_anomaly", "high", {"detail": "3 failures in 60s"})
    flags = await db.get_active_risk_flags("UE_HASH_TEST")
    assert len(flags) == 1
    assert flags[0]["flag_type"] == "auth_anomaly"
    assert flags[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_log_summary_disclosure():
    await db.log_summary_disclosure(
        request_id="REQ-001",
        pseudonym="UE_HASH_TEST",
        network_b_id="Network_B",
        summary_payload={"auth_stability": "high"},
        requested_fields=["auth_stability"],
    )
    disclosures = db._MEMORY_STORE["summary_disclosure"]
    assert len(disclosures) == 1
    assert disclosures[0]["request_id"] == "REQ-001"
