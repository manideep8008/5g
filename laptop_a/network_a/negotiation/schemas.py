"""Wire schemas for the negotiation endpoints (docs/design/protocol.md).

These models are the contract Network B codes against; Network B keeps a
byte-identical copy in its own ``contract`` package, mirroring how the
one-shot summary schema is shared today.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class NegotiationContext(BaseModel):
    requested_slice: str
    requested_dnn: str
    requested_service: str


class SessionOpenRequest(BaseModel):
    request_id: str
    ue_pseudonym: str
    requester_id: str = "network_b"
    context: NegotiationContext


class MinimalAttestation(BaseModel):
    """The free (cost-0) starter disclosure at session open."""

    behaviour_label: str
    recent_anomaly: bool
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)


class SessionOpenResponse(BaseModel):
    session_id: str
    grammar_version: int
    minimal_attestation: MinimalAttestation
    budget_total: int
    budget_remaining: int


class QueryRequest(BaseModel):
    session_id: str
    predicate: str
    args: dict[str, str] = Field(default_factory=dict)


QueryStatus = Literal["answered", "rejected", "refused", "unavailable"]


class QueryResponse(BaseModel):
    """Only ``answered`` carries an answer and a debit; every other status
    is information-free and cost-free by design."""

    status: QueryStatus
    answer: str | None = None
    reason: str | None = None
    cost: int | None = None
    budget_remaining: int
    grounded: bool | None = None


class CloseRequest(BaseModel):
    session_id: str
    final_tier: str


class CloseResponse(BaseModel):
    session_id: str
    transcript_hash: str
