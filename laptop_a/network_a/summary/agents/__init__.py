"""Network A's responder agent team.

Answers negotiation predicates from the UE's evidence base. The division of
labor mirrors the thesis architecture:

- ``trend_agent``      — temporal reasoning (trend)
- ``anomaly_agent``    — flag lifecycle reasoning (anomaly_status, flag_age)
- ``behavioral_agent`` — habitual behavior (stability, novelty, regularity)
- ``grounding``        — the normative rules from docs/design/grammar.md;
                         the single source of truth every answer is checked
                         against
- ``verifier``         — blocks any answer the grounding rules do not entail
- ``orchestrator``     — routes a validated query to its responder under a
                         timeout and returns a fail-closed result

The v1 responders are deterministic and delegate to ``grounding`` directly.
LLM-backed responders can replace any ``answer`` function later without
touching the verifier or the boundary — that is the point of keeping
generator and checker separate.
"""
