"""Behavioral analyst: what is habitual for this UE, and is the current
request consistent with it?

Owns: auth_stability, pdu_stability, traffic_pattern, session_regularity,
resource_novelty.

v1 is deterministic and delegates to the grounding rules. An LLM-backed
variant replaces this ``answer`` function only — the verifier still checks
its output against the same rules.
"""

from __future__ import annotations

from network_a.summary.agents import grounding
from network_a.summary.agents.evidence import Evidence


async def answer(predicate: str, args: dict[str, str], evidence: Evidence) -> str | None:
    return grounding.ground(predicate, args, evidence)
