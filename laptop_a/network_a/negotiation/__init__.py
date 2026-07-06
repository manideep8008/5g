"""Negotiated attestation boundary for Network A.

Everything that leaves Network A during a negotiation session passes through
this package: the question grammar bounds what can be asked, the budget
ledger bounds how much can be answered, and (in later phases) the session
state machine and egress validation bound each concrete answer.
"""
