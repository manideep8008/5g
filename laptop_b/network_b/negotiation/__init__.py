"""Network B's side of the negotiated attestation protocol.

- ``belief``         — risk-interval model over partially known facets;
                       decides when the tier is certain enough to stop
- ``decision_agent`` — the ask/decide loop driving a negotiation session
- ``session_client`` — signed HTTP client for Network A's attestation
                       endpoints, fail-closed like the one-shot fetch
"""
