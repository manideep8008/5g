"""Boundary control: the only door evidence-derived answers leave through.

Implements the normative gate order from docs/design/protocol.md for the
three session operations. HTTP concerns stay in the API layer; everything
here is directly testable offline.

Gate order for a query: session state → grammar → budget → responder
(with grounding verification inside the orchestrator) → egress validation →
atomic debit. Failures never debit, and every turn — including rejected and
refused ones — lands on the transcript.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from network_a import db
from network_a.negotiation.grammar import GrammarError, load_grammar
from network_a.negotiation.ledger import BudgetExhausted, BudgetLedger
from network_a.negotiation.schemas import (
    CloseRequest,
    CloseResponse,
    MinimalAttestation,
    QueryRequest,
    QueryResponse,
    SessionOpenRequest,
    SessionOpenResponse,
)
from network_a.negotiation.session import Session, SessionState, SessionStore
from network_a.summary.agents import orchestrator
from network_a.summary.agents.evidence import gather_evidence
from network_a.summary.summary_generator import (
    compute_confidence,
    compute_overall_risk,
    generate_behavioural_summary,
    recommend_tier,
)

logger = logging.getLogger(__name__)


class NoEvidence(Exception):
    """The pseudonym has no behavioural history on Network A."""


_STORE = SessionStore()
_LEDGER: BudgetLedger | None = None


def _ledger() -> BudgetLedger:
    global _LEDGER
    if _LEDGER is None:
        grammar = load_grammar()
        _LEDGER = BudgetLedger(
            total=grammar.budget_total, window_sec=grammar.budget_window_sec
        )
    return _LEDGER


def reset_for_tests() -> None:
    """Drop live sessions and the cached ledger (test isolation)."""
    global _LEDGER
    _STORE.clear()
    _LEDGER = None


async def open_session(
    req: SessionOpenRequest, now: datetime | None = None
) -> SessionOpenResponse:
    """Open a negotiation session: snapshot evidence once, disclose the free
    minimal attestation, and report the current window budget."""
    now = now or datetime.now(timezone.utc)

    evidence = await gather_evidence(req.ue_pseudonym, now=now)
    if evidence is None:
        raise NoEvidence(req.ue_pseudonym)

    summary = generate_behavioural_summary(evidence.profile)
    overall_risk = compute_overall_risk(evidence.profile)
    attestation = MinimalAttestation(
        behaviour_label=summary.behaviour_label.value,
        recent_anomaly=summary.recent_anomaly,
        recommendation=recommend_tier(overall_risk).value,
        confidence=compute_confidence(evidence.profile, overall_risk),
    )

    grammar = load_grammar()
    budget = await _ledger().status(req.ue_pseudonym, req.requester_id, now=now)
    session = _STORE.open(
        ue_pseudonym=req.ue_pseudonym,
        requester_id=req.requester_id,
        grammar_version=grammar.version,
        evidence=evidence,
        now=now,
    )
    session.entries.append(
        {"turn": 0, "type": "minimal_attestation", "payload": attestation.model_dump()}
    )
    logger.info(
        "session %s opened for %s (requester=%s, budget=%d/%d)",
        session.session_id, req.ue_pseudonym, req.requester_id,
        budget.remaining, budget.total,
    )

    return SessionOpenResponse(
        session_id=session.session_id,
        grammar_version=grammar.version,
        minimal_attestation=attestation,
        budget_total=budget.total,
        budget_remaining=budget.remaining,
    )


def _record(session: Session, req: QueryRequest, resp: QueryResponse) -> QueryResponse:
    """Append the turn to the session transcript and pass the response through."""
    session.entries.append(
        {
            "turn": session.turns,
            "type": "query",
            "predicate": req.predicate,
            "args": req.args,
            **resp.model_dump(exclude_none=True),
        }
    )
    return resp


async def handle_query(
    req: QueryRequest, now: datetime | None = None
) -> QueryResponse:
    """Run one query through the full gate sequence. Callers translate
    SessionNotFound / SessionExpired into their transport's error shape."""
    now = now or datetime.now(timezone.utc)
    grammar = load_grammar()
    session = _STORE.begin_turn(req.session_id, now=now)
    remaining = (
        await _ledger().status(session.ue_pseudonym, session.requester_id, now=now)
    ).remaining

    try:
        spec = grammar.validate_query(req.predicate, req.args)
    except GrammarError as exc:
        logger.warning(
            "off-grammar probe on session %s from %s: %s",
            req.session_id, session.requester_id, exc,
        )
        return _record(session, req, QueryResponse(
            status="rejected", reason="off_grammar", budget_remaining=remaining,
        ))

    if spec.cost > remaining:
        session.state = SessionState.EXHAUSTED
        return _record(session, req, QueryResponse(
            status="refused", reason="budget_exhausted", budget_remaining=remaining,
        ))

    result = await orchestrator.answer_query(spec, req.args, session.evidence)
    if result.status == "unavailable":
        return _record(session, req, QueryResponse(
            status="unavailable", reason=result.reason, budget_remaining=remaining,
        ))

    try:
        grammar.validate_answer(spec.name, result.answer)
    except GrammarError:
        # Defense in depth: the verifier should make this unreachable.
        logger.error(
            "egress blocked out-of-domain answer %r for %s", result.answer, spec.name
        )
        return _record(session, req, QueryResponse(
            status="unavailable", reason="egress_blocked", budget_remaining=remaining,
        ))

    try:
        budget = await _ledger().debit(
            session.ue_pseudonym, session.requester_id, spec.cost, now=now
        )
    except BudgetExhausted:
        # Lost a race against a concurrent debit in the same window.
        session.state = SessionState.EXHAUSTED
        return _record(session, req, QueryResponse(
            status="refused", reason="budget_exhausted", budget_remaining=remaining,
        ))

    if budget.remaining == 0:
        session.state = SessionState.EXHAUSTED

    return _record(session, req, QueryResponse(
        status="answered",
        answer=result.answer,
        cost=spec.cost,
        budget_remaining=budget.remaining,
        grounded=True,
    ))


def compute_transcript_hash(record: dict) -> str:
    """SHA-256 over the canonical JSON encoding of a sealed transcript."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def close_session(
    req: CloseRequest, now: datetime | None = None
) -> CloseResponse:
    """Seal the transcript, persist it, and retire the session id."""
    now = now or datetime.now(timezone.utc)
    session = _STORE.close(req.session_id)

    record = {
        "session_id": session.session_id,
        "ue_pseudonym": session.ue_pseudonym,
        "requester_id": session.requester_id,
        "grammar_version": session.grammar_version,
        "opened_at": session.opened_at.isoformat(),
        "closed_at": now.isoformat(),
        "final_tier": req.final_tier,
        "entries": session.entries,
    }
    transcript_hash = compute_transcript_hash(record)

    await db.insert_transcript(
        session_id=session.session_id,
        pseudonym=session.ue_pseudonym,
        requester_id=session.requester_id,
        grammar_version=session.grammar_version,
        opened_at=session.opened_at,
        closed_at=now,
        final_tier=req.final_tier,
        entries=session.entries,
        transcript_hash=transcript_hash,
    )
    logger.info(
        "session %s closed: tier=%s, %d turns, transcript %s",
        session.session_id, req.final_tier, session.turns, transcript_hash[:12],
    )

    return CloseResponse(session_id=session.session_id, transcript_hash=transcript_hash)
