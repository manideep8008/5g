"""Grounding verifier: no answer leaves Network A unless the normative
rules entail it.

The verifier is deliberately separate from the responders that produce
answers — a component checking its own output is not verification. With the
v1 deterministic responders this check is trivially satisfied; its value is
that it never changes when responders become LLM-backed.
"""

from __future__ import annotations

from network_a.summary.agents import grounding
from network_a.summary.agents.evidence import Evidence


def verify(predicate: str, args: dict[str, str], evidence: Evidence, answer: str) -> bool:
    """True iff the grounding rules entail exactly this answer."""
    expected = grounding.ground(predicate, args, evidence)
    return expected is not None and expected == answer
