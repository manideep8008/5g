"""Tests for profile_builder — aggregating session data per UE."""

import pytest
from datetime import datetime, timezone

from network_a import db
from network_a.summary.profile_builder import build_profile


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


async def _seed_identity(pseudonym="UE_HASH_TEST"):
    await db.insert_identity(pseudonym, f"hmac_{pseudonym}", "Network_B")


@pytest.mark.asyncio
async def test_build_profile_no_sessions():
    await _seed_identity()
    profile = await build_profile("UE_HASH_TEST")
    assert profile is None


@pytest.mark.asyncio
async def test_build_profile_single_session():
    await _seed_identity()
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        registration_success=True,
        auth_attempts=5,
        auth_failures=1,
        pdu_attempts=3,
        pdu_failures=0,
        bytes_uplink=1000,
        bytes_downlink=5000,
        peak_throughput_kbps=100,
        spike_count=0,
        requested_slice="eMBB",
        requested_dnn="internet",
    )

    profile = await build_profile("UE_HASH_TEST")
    assert profile is not None
    assert profile.pseudonym == "UE_HASH_TEST"
    assert profile.session_count == 1
    assert profile.total_auth_attempts == 5
    assert profile.total_auth_failures == 1
    assert profile.auth_failure_rate == 0.2
    assert profile.total_pdu_attempts == 3
    assert profile.total_pdu_failures == 0
    assert profile.pdu_failure_rate == 0.0
    assert profile.total_bytes_uplink == 1000
    assert profile.total_bytes_downlink == 5000
    assert profile.peak_throughput_kbps == 100
    assert profile.spike_rate == 0.0
    assert profile.known_slices == ["eMBB"]
    assert profile.known_dnns == ["internet"]
    assert profile.has_active_risk_flags is False


@pytest.mark.asyncio
async def test_build_profile_multiple_sessions():
    await _seed_identity()
    for i in range(4):
        await db.insert_session(
            pseudonym="UE_HASH_TEST",
            started_at=datetime.now(timezone.utc),
            auth_attempts=10,
            auth_failures=i,
            pdu_attempts=5,
            pdu_failures=1 if i > 2 else 0,
            spike_count=1 if i % 2 == 0 else 0,
            requested_slice="eMBB" if i < 3 else "URLLC",
        )

    profile = await build_profile("UE_HASH_TEST")
    assert profile.session_count == 4
    assert profile.total_auth_attempts == 40
    assert profile.total_auth_failures == 6  # 0+1+2+3
    assert profile.auth_failure_rate == 0.15
    assert profile.total_pdu_failures == 1
    assert profile.total_spike_count == 2
    assert profile.spike_rate == 0.5
    assert sorted(profile.known_slices) == ["URLLC", "eMBB"]


@pytest.mark.asyncio
async def test_build_profile_with_risk_flags():
    await _seed_identity()
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        auth_attempts=1,
    )
    await db.insert_risk_flag("UE_HASH_TEST", "auth_anomaly", "high")

    profile = await build_profile("UE_HASH_TEST")
    assert profile.has_active_risk_flags is True


@pytest.mark.asyncio
async def test_build_profile_zero_auth_attempts():
    await _seed_identity()
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        auth_attempts=0,
        auth_failures=0,
    )

    profile = await build_profile("UE_HASH_TEST")
    assert profile.auth_failure_rate == 0.0


@pytest.mark.asyncio
async def test_build_profile_unknown_pseudonym():
    profile = await build_profile("NONEXISTENT")
    assert profile is None


@pytest.mark.asyncio
async def test_build_profile_peak_throughput_max():
    await _seed_identity()
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        peak_throughput_kbps=500,
    )
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        peak_throughput_kbps=1200,
    )
    await db.insert_session(
        pseudonym="UE_HASH_TEST",
        started_at=datetime.now(timezone.utc),
        peak_throughput_kbps=800,
    )

    profile = await build_profile("UE_HASH_TEST")
    assert profile.peak_throughput_kbps == 1200
