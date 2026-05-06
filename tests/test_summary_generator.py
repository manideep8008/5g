"""Tests for summary_generator — real DB-backed summary generation."""

import pytest
from datetime import datetime, timezone

from network_a import db
from network_a.summary.summary_generator import generate_summary
from network_a.summary.summary_schema import (
    NetworkBContext,
    SummaryRequest,
    Tier,
)


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


def _make_request(pseudonym="UE_HASH_TEST", request_id="REQ-001"):
    return SummaryRequest(
        request_id=request_id,
        ue_pseudonym=pseudonym,
        network_b_context=NetworkBContext(
            requested_slice="eMBB",
            requested_dnn="internet",
            requested_service="standard_data",
        ),
    )


async def _seed_ue_with_sessions(pseudonym="UE_HASH_TEST", count=5, **session_kwargs):
    await db.insert_identity(pseudonym, f"hmac_{pseudonym}", "Network_B")
    defaults = dict(
        registration_success=True,
        auth_attempts=10,
        auth_failures=0,
        pdu_attempts=5,
        pdu_failures=0,
        bytes_uplink=1000,
        bytes_downlink=5000,
        spike_count=0,
        requested_slice="eMBB",
        requested_dnn="internet",
    )
    defaults.update(session_kwargs)
    for _ in range(count):
        await db.insert_session(
            pseudonym=pseudonym,
            started_at=datetime.now(timezone.utc),
            **defaults,
        )


@pytest.mark.asyncio
async def test_generate_summary_unknown_pseudonym():
    result = await generate_summary(_make_request("NONEXISTENT"))
    assert result is None


@pytest.mark.asyncio
async def test_generate_summary_no_sessions():
    await db.insert_identity("UE_HASH_TEST", "hmac_test", "Network_B")
    result = await generate_summary(_make_request())
    assert result is None


@pytest.mark.asyncio
async def test_generate_summary_normal_ue():
    await _seed_ue_with_sessions()
    result = await generate_summary(_make_request())

    assert result is not None
    assert result.request_id == "REQ-001"
    assert result.ue_pseudonym == "UE_HASH_TEST"
    assert result.summary.auth_stability.value == "high"
    assert result.summary.pdu_session_stability.value == "high"
    assert result.summary.traffic_pattern.value == "stable"
    assert result.summary.recent_anomaly is False
    assert result.summary.behaviour_label.value == "normal"
    assert result.network_a_recommendation == Tier.T3_FULL_ACCESS.value
    assert result.confidence > 0.8
    assert result.privacy_level == "summary_only"


@pytest.mark.asyncio
async def test_generate_summary_high_failure_ue():
    await _seed_ue_with_sessions(auth_failures=5, pdu_failures=2, spike_count=2)
    result = await generate_summary(_make_request())

    assert result is not None
    assert result.summary.auth_stability.value != "high"
    assert result.network_a_recommendation != Tier.T3_FULL_ACCESS.value


@pytest.mark.asyncio
async def test_generate_summary_with_risk_flags():
    await _seed_ue_with_sessions()
    await db.insert_risk_flag("UE_HASH_TEST", "auth_burst", "medium")

    result = await generate_summary(_make_request())
    assert result is not None
    assert result.summary.recent_anomaly is True


@pytest.mark.asyncio
async def test_generate_summary_disallowed_field():
    await _seed_ue_with_sessions()
    req = SummaryRequest(
        request_id="REQ-BAD",
        ue_pseudonym="UE_HASH_TEST",
        requested_fields=["auth_stability", "raw_imsi"],
        network_b_context=NetworkBContext(
            requested_slice="eMBB",
            requested_dnn="internet",
            requested_service="standard_data",
        ),
    )
    with pytest.raises(ValueError, match="not in the allowlist"):
        await generate_summary(req)


@pytest.mark.asyncio
async def test_generate_summary_logs_disclosure():
    await _seed_ue_with_sessions()
    await generate_summary(_make_request())

    disclosures = db._MEMORY_STORE["summary_disclosure"]
    assert len(disclosures) == 1
    assert disclosures[0]["request_id"] == "REQ-001"
    assert disclosures[0]["pseudonym"] == "UE_HASH_TEST"
    assert "auth_stability" in disclosures[0]["summary_payload"]


@pytest.mark.asyncio
async def test_generate_summary_confidence_inversely_correlated():
    await _seed_ue_with_sessions(pseudonym="UE_GOOD")
    await _seed_ue_with_sessions(
        pseudonym="UE_BAD",
        auth_failures=8,
        pdu_failures=4,
        spike_count=5,
    )
    await db.insert_risk_flag("UE_BAD", "anomaly", "high")

    good_result = await generate_summary(_make_request("UE_GOOD"))
    bad_result = await generate_summary(_make_request("UE_BAD"))

    assert good_result.confidence > bad_result.confidence


@pytest.mark.asyncio
async def test_generate_summary_tier_recommendation_levels():
    await _seed_ue_with_sessions(pseudonym="UE_CLEAN")
    result = await generate_summary(_make_request("UE_CLEAN"))
    assert result.network_a_recommendation == Tier.T3_FULL_ACCESS.value

    await _seed_ue_with_sessions(
        pseudonym="UE_RISKY",
        auth_failures=9,
        pdu_failures=4,
        spike_count=8,
    )
    await db.insert_risk_flag("UE_RISKY", "severe_anomaly", "critical")
    risky_result = await generate_summary(_make_request("UE_RISKY"))
    assert risky_result.network_a_recommendation in [
        Tier.T0_REJECT.value,
        Tier.T1_RESTRICTED_ACCESS.value,
    ]
