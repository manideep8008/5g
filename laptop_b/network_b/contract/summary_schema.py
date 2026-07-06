from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class AuthStability(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PduSessionStability(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TrafficPattern(str, Enum):
    STABLE = "stable"
    MODERATE = "moderate"
    VOLATILE = "volatile"


class BehaviourLabel(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"


ALLOWED_FIELDS = frozenset({
    "auth_stability",
    "pdu_session_stability",
    "traffic_pattern",
    "known_slice_usage",
    "recent_anomaly",
    "behaviour_label",
})


class UeBehaviouralSummary(BaseModel):
    auth_stability: AuthStability
    pdu_session_stability: PduSessionStability
    traffic_pattern: TrafficPattern
    known_slice_usage: list[str] = Field(default_factory=list)
    recent_anomaly: bool = False
    behaviour_label: BehaviourLabel


class NetworkBContext(BaseModel):
    requested_slice: str
    requested_dnn: str
    requested_service: str


class SummaryRequest(BaseModel):
    request_id: str
    ue_pseudonym: str
    requested_fields: list[str] = Field(default_factory=lambda: list(ALLOWED_FIELDS))
    network_b_context: NetworkBContext


class SummaryResponse(BaseModel):
    request_id: str
    ue_pseudonym: str
    summary: UeBehaviouralSummary
    network_a_recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)
    privacy_level: Literal["summary_only"] = "summary_only"
    issued_at: datetime
    summary_window_sec: int = 86400


class AccessRequest(BaseModel):
    event_type: Literal["UE_ACCESS_REQUEST_AT_NETWORK_B"] = "UE_ACCESS_REQUEST_AT_NETWORK_B"
    request_id: str
    ue_pseudonym: str
    requested_network: str = "Network_B"
    requested_slice: str
    requested_dnn: str
    requested_service: str
    timestamp: datetime


class Tier(str, Enum):
    T0_REJECT = "T0_REJECT"
    T1_RESTRICTED_ACCESS = "T1_RESTRICTED_ACCESS"
    T2_MONITORED_ACCESS = "T2_MONITORED_ACCESS"
    T3_FULL_ACCESS = "T3_FULL_ACCESS"


TIER_ORDER = {
    Tier.T0_REJECT: 0,
    Tier.T1_RESTRICTED_ACCESS: 1,
    Tier.T2_MONITORED_ACCESS: 2,
    Tier.T3_FULL_ACCESS: 3,
}


class PolicyEngineMetadata(BaseModel):
    llm_model_id: str = "rules_only"
    llm_temperature: float = 0.0
    llm_proposed_tier: str | None = None
    safety_floor_clipped: bool = False
    safety_floor_reason: str | None = None
    deterministic_max_tier: str
    rag_enabled: bool = False
    rag_adequate: bool | None = None
    # Negotiated-attestation audit fields (docs/design/protocol.md).
    negotiated: bool = False
    negotiation_transcript_hash: str | None = None
    negotiation_budget_spent: int | None = None


class SimulatedEnforcement(BaseModel):
    bandwidth_cap_mbps: int | None = None
    monitoring_interval_sec: int | None = None
    allowed_services: list[str] = Field(default_factory=lambda: ["standard_data"])


ENFORCEMENT_MAP = {
    Tier.T0_REJECT: SimulatedEnforcement(
        bandwidth_cap_mbps=0,
        monitoring_interval_sec=None,
        allowed_services=[],
    ),
    Tier.T1_RESTRICTED_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=10,
        monitoring_interval_sec=30,
        allowed_services=["standard_data"],
    ),
    Tier.T2_MONITORED_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=50,
        monitoring_interval_sec=60,
        allowed_services=["standard_data"],
    ),
    Tier.T3_FULL_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=None,
        monitoring_interval_sec=None,
        allowed_services=["standard_data", "voice", "video", "iot"],
    ),
}


SourceType = Literal["policy", "precedent", "principle"]


class EvidenceSnippet(BaseModel):
    snippet_id: str
    source_type: SourceType
    source_id: str
    source_title: str
    content: str
    similarity: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, str] = Field(default_factory=dict)


class AdequacyReport(BaseModel):
    facet_coverage: dict[str, int]
    distinct_facets: int
    min_facets_required: int
    adequate: bool
    expansion_triggered: bool = False
    notes: list[str] = Field(default_factory=list)


class EvidenceBundle(BaseModel):
    bundle_id: str
    retrieved_at: datetime
    query_text: str
    snippets: list[EvidenceSnippet] = Field(default_factory=list)
    adequacy: AdequacyReport


class AccessDecision(BaseModel):
    request_id: str
    ue_pseudonym: str
    final_tier: Tier
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str
    policy_engine_metadata: PolicyEngineMetadata
    simulated_enforcement: SimulatedEnforcement
    decided_at: datetime
    summary: UeBehaviouralSummary | None = None
    evidence_bundle: EvidenceBundle | None = None
