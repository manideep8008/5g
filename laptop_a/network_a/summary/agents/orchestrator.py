"""Routes a validated query to its responder agent, fail-closed.

Sits between boundary control (which has already validated the query
against the grammar and the budget) and the responder team. Every failure
mode — timeout, crash, insufficient data, an answer the grounding rules do
not entail — collapses to ``unavailable``, which the protocol treats as
non-informative and never debits.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Literal

from network_a.negotiation.grammar import PredicateSpec
from network_a.summary.agents import anomaly_agent, behavioral_agent, trend_agent, verifier
from network_a.summary.agents.evidence import Evidence

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 5.0

Responder = Callable[[str, dict[str, str], Evidence], Awaitable[str | None]]

RESPONDERS: dict[str, Responder] = {
    "trend": trend_agent.answer,
    "anomaly": anomaly_agent.answer,
    "behavioral": behavioral_agent.answer,
}


@dataclass(frozen=True)
class AgentAnswer:
    status: Literal["answered", "unavailable"]
    answer: str | None = None
    reason: str | None = None


def _unavailable(reason: str) -> AgentAnswer:
    return AgentAnswer(status="unavailable", reason=reason)


async def answer_query(
    spec: PredicateSpec,
    args: dict[str, str],
    evidence: Evidence,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> AgentAnswer:
    """Run the responder for an already-validated query and verify its answer."""
    responder = RESPONDERS[spec.responder]

    try:
        answer = await asyncio.wait_for(
            responder(spec.name, args, evidence), timeout=timeout_sec
        )
    except TimeoutError:
        logger.warning("responder '%s' timed out on %s", spec.responder, spec.name)
        return _unavailable("timeout")
    except Exception:
        logger.exception("responder '%s' crashed on %s", spec.responder, spec.name)
        return _unavailable("responder_error")

    if answer is None:
        return _unavailable("insufficient_data")

    if not verifier.verify(spec.name, args, evidence, answer):
        logger.warning(
            "verifier blocked ungrounded answer %r for %s from '%s'",
            answer, spec.name, spec.responder,
        )
        return _unavailable("grounding_failed")

    return AgentAnswer(status="answered", answer=answer)
