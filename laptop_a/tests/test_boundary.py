"""Offline tests for boundary control: the full gate sequence, session
lifecycle, budget accounting, and transcript sealing — no HTTP."""

from datetime import datetime, timedelta, timezone

import pytest

from network_a import db
from network_a.api.routes import seed_scenarios
from network_a.negotiation import boundary
from network_a.negotiation.schemas import (
    CloseRequest,
    NegotiationContext,
    QueryRequest,
    SessionOpenRequest,
)
from network_a.negotiation.session import SessionExpired, SessionNotFound

NOW = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def reset_state():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    boundary.reset_for_tests()
    yield
    db.reset_memory_store()
    boundary.reset_for_tests()


def open_request(pseudonym: str) -> SessionOpenRequest:
    return SessionOpenRequest(
        request_id="req-1",
        ue_pseudonym=pseudonym,
        requester_id="network_b",
        context=NegotiationContext(
            requested_slice="eMBB", requested_dnn="internet",
            requested_service="standard_data",
        ),
    )


async def open_for(pseudonym: str, now: datetime = NOW):
    await seed_scenarios()
    return await boundary.open_session(open_request(pseudonym), now=now)


def query(session_id: str, predicate: str, **args) -> QueryRequest:
    return QueryRequest(session_id=session_id, predicate=predicate, args=args)


# ── open ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_open_returns_minimal_attestation_and_budget():
    resp = await open_for("UE_SIM_RECOVERING")

    assert resp.grammar_version == 1
    assert resp.budget_total == 100
    assert resp.budget_remaining == 100
    assert resp.minimal_attestation.behaviour_label == "anomalous"
    assert resp.minimal_attestation.recent_anomaly is True


@pytest.mark.asyncio
async def test_open_unknown_ue_raises_no_evidence():
    with pytest.raises(boundary.NoEvidence):
        await boundary.open_session(open_request("UE_NEVER_SEEN"), now=NOW)


# ── the demo negotiation, end to end ─────────────────────────────


@pytest.mark.asyncio
async def test_recovering_negotiation_full_flow():
    opened = await open_for("UE_SIM_RECOVERING")
    sid = opened.session_id

    trend = await boundary.handle_query(
        query(sid, "trend", facet="auth_failures"), now=NOW
    )
    assert trend.status == "answered"
    assert trend.answer == "decreasing"
    assert trend.cost == 10
    assert trend.budget_remaining == 90

    status = await boundary.handle_query(query(sid, "anomaly_status"), now=NOW)
    assert status.answer == "resolved"
    assert status.budget_remaining == 65

    closed = await boundary.close_session(
        CloseRequest(session_id=sid, final_tier="T2_MONITORED_ACCESS"), now=NOW
    )
    assert len(closed.transcript_hash) == 64

    stored = await db.get_transcript(sid)
    assert stored is not None
    assert stored["final_tier"] == "T2_MONITORED_ACCESS"
    assert stored["transcript_hash"] == closed.transcript_hash
    # Turn 0 attestation + two query turns, all on the record.
    assert len(stored["entries"]) == 3
    assert stored["entries"][0]["type"] == "minimal_attestation"
    assert stored["entries"][1]["answer"] == "decreasing"


@pytest.mark.asyncio
async def test_session_is_gone_after_close():
    opened = await open_for("UE_SIM_NORMAL")
    await boundary.close_session(
        CloseRequest(session_id=opened.session_id, final_tier="T3_FULL_ACCESS"), now=NOW
    )
    with pytest.raises(SessionNotFound):
        await boundary.handle_query(
            query(opened.session_id, "anomaly_status"), now=NOW
        )


# ── failure gates: no debit on any non-answer ────────────────────


@pytest.mark.asyncio
async def test_off_grammar_is_rejected_without_debit():
    opened = await open_for("UE_SIM_NORMAL")

    resp = await boundary.handle_query(
        query(opened.session_id, "raw_features"), now=NOW
    )
    assert resp.status == "rejected"
    assert resp.reason == "off_grammar"
    assert resp.budget_remaining == 100

    # Session survives a rejection; a valid query still answers.
    ok = await boundary.handle_query(
        query(opened.session_id, "anomaly_status"), now=NOW
    )
    assert ok.status == "answered"


@pytest.mark.asyncio
async def test_insufficient_data_is_unavailable_without_debit():
    await db.insert_identity("UE_SPARSE", "hmac_sparse", "Network_B")
    await db.insert_session(
        pseudonym="UE_SPARSE", started_at=NOW - timedelta(hours=1),
        auth_attempts=5, auth_failures=0,
    )
    opened = await boundary.open_session(open_request("UE_SPARSE"), now=NOW)

    resp = await boundary.handle_query(
        query(opened.session_id, "trend", facet="auth_failures"), now=NOW
    )
    assert resp.status == "unavailable"
    assert resp.reason == "insufficient_data"
    assert resp.budget_remaining == 100


@pytest.mark.asyncio
async def test_budget_exhaustion_refuses_whole_queries():
    opened = await open_for("UE_SIM_SUSPICIOUS")
    sid = opened.session_id

    for expected_remaining in (75, 50, 25, 0):
        resp = await boundary.handle_query(query(sid, "anomaly_status"), now=NOW)
        assert resp.status == "answered"
        assert resp.budget_remaining == expected_remaining

    refused = await boundary.handle_query(query(sid, "anomaly_status"), now=NOW)
    assert refused.status == "refused"
    assert refused.reason == "budget_exhausted"
    assert refused.budget_remaining == 0


@pytest.mark.asyncio
async def test_budget_persists_across_sessions_in_same_window():
    opened = await open_for("UE_SIM_SUSPICIOUS")
    await boundary.handle_query(
        query(opened.session_id, "anomaly_status"), now=NOW
    )
    await boundary.close_session(
        CloseRequest(session_id=opened.session_id, final_tier="T1_RESTRICTED_ACCESS"),
        now=NOW,
    )

    reopened = await boundary.open_session(
        open_request("UE_SIM_SUSPICIOUS"), now=NOW + timedelta(seconds=60)
    )
    assert reopened.budget_remaining == 75


# ── protocol limits ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_idle_timeout_closes_session():
    opened = await open_for("UE_SIM_NORMAL")

    with pytest.raises(SessionExpired) as exc:
        await boundary.handle_query(
            query(opened.session_id, "anomaly_status"),
            now=NOW + timedelta(seconds=121),
        )
    assert exc.value.reason == "idle_timeout"

    with pytest.raises(SessionNotFound):
        await boundary.handle_query(query(opened.session_id, "anomaly_status"), now=NOW)


@pytest.mark.asyncio
async def test_max_turns_closes_session():
    opened = await open_for("UE_SIM_NORMAL")

    for _ in range(12):
        await boundary.handle_query(query(opened.session_id, "flag_age"), now=NOW)

    with pytest.raises(SessionExpired) as exc:
        await boundary.handle_query(query(opened.session_id, "flag_age"), now=NOW)
    assert exc.value.reason == "max_turns"


@pytest.mark.asyncio
async def test_close_unknown_session_raises():
    with pytest.raises(SessionNotFound):
        await boundary.close_session(
            CloseRequest(session_id="nope", final_tier="T1_RESTRICTED_ACCESS"), now=NOW
        )


# ── transcript integrity ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_transcript_hash_is_recomputable():
    opened = await open_for("UE_SIM_RECOVERING")
    await boundary.handle_query(
        query(opened.session_id, "trend", facet="auth_failures"), now=NOW
    )
    closed = await boundary.close_session(
        CloseRequest(session_id=opened.session_id, final_tier="T2_MONITORED_ACCESS"),
        now=NOW,
    )

    stored = await db.get_transcript(opened.session_id)
    record = {
        "session_id": stored["session_id"],
        "ue_pseudonym": stored["pseudonym"],
        "requester_id": stored["requester_id"],
        "grammar_version": stored["grammar_version"],
        "opened_at": stored["opened_at"],
        "closed_at": stored["closed_at"],
        "final_tier": stored["final_tier"],
        "entries": stored["entries"],
    }
    assert boundary.compute_transcript_hash(record) == closed.transcript_hash


@pytest.mark.asyncio
async def test_rejected_turns_are_on_the_transcript():
    """Probing attempts are part of the audit record."""
    opened = await open_for("UE_SIM_NORMAL")
    await boundary.handle_query(query(opened.session_id, "raw_features"), now=NOW)
    await boundary.close_session(
        CloseRequest(session_id=opened.session_id, final_tier="T3_FULL_ACCESS"), now=NOW
    )

    stored = await db.get_transcript(opened.session_id)
    probe = stored["entries"][1]
    assert probe["status"] == "rejected"
    assert probe["predicate"] == "raw_features"
