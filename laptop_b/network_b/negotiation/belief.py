"""Belief state for the decision agent: risk as an interval, not a number.

The one-shot path knows all five summary facets and computes one risk score.
During a negotiation, facets are only partially known, so risk is a bound:
unknown facets contribute their best case to ``risk_min`` and their worst
case to ``risk_max``. The agent may stop as soon as both bounds map to the
same tier — unknowns provably cannot change the decision — and when it must
stop early it grants against ``risk_max``, never the optimistic bound.

Weights and facet risk values mirror the one-shot policy engine
(``policy_engine.FIELD_RISK_MAP`` / ``DEFAULT_WEIGHTS``); negotiated facts
(trend, anomaly resolution) enter as multipliers on those same terms, so the
deterministic ceiling moves only because deterministic inputs changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from network_b.contract.summary_schema import TIER_ORDER, Tier
from network_b.policy.policy_engine import risk_to_max_tier

# Facet keys in Beliefs.facts / Beliefs.unresolvable.
AUTH = "auth_stability"
PDU = "pdu_stability"
TRAFFIC = "traffic_pattern"
ANOMALY = "anomaly_status"
TREND_AUTH = "trend_auth_failures"
TREND_TRAFFIC = "trend_traffic_spikes"

# Mirrors of the one-shot risk model (policy_engine.py).
WEIGHTS = {AUTH: 0.25, PDU: 0.20, TRAFFIC: 0.20, ANOMALY: 0.20, "behaviour": 0.15}
LEVEL_RISK = {"high": 0.0, "medium": 0.5, "low": 1.0}
TRAFFIC_RISK = {"stable": 0.0, "moderate": 0.5, "volatile": 1.0}
LABEL_RISK = {"normal": 0.0, "suspicious": 0.5, "anomalous": 1.0}

# Negotiated-fact multipliers on the base terms.
TREND_DISCOUNT = 0.5          # a decreasing trend halves the facet's risk term
ANOMALY_MULT = {"none": 0.0, "resolved": 0.25, "active": 1.0}

# Mirror of grammar.yaml v1 costs — Network B plans with these, Network A
# enforces the real ones. A version mismatch aborts the negotiation.
SUPPORTED_GRAMMAR_VERSION = 1
COST = {AUTH: 15, PDU: 15, TRAFFIC: 15, ANOMALY: 25, "trend": 10}


@dataclass
class Beliefs:
    """Facts established so far in one negotiation."""

    behaviour_label: str
    recent_anomaly: bool
    facts: dict[str, str] = field(default_factory=dict)
    unresolvable: set[str] = field(default_factory=set)


def _facet_bounds(
    beliefs: Beliefs, facet: str, risk_map: dict[str, float], trend_key: str | None
) -> tuple[float, float]:
    weight = WEIGHTS[facet]
    value = beliefs.facts.get(facet)

    if value is None:
        if facet in beliefs.unresolvable:
            return (weight, weight)  # unanswerable → assume worst, forever
        return (0.0, weight)

    base = risk_map[value] * weight
    if base == 0.0 or trend_key is None:
        return (base, base)

    trend = beliefs.facts.get(trend_key)
    if trend is not None:
        mult = TREND_DISCOUNT if trend == "decreasing" else 1.0
        return (base * mult, base * mult)
    if trend_key in beliefs.unresolvable:
        return (base, base)
    return (base * TREND_DISCOUNT, base)  # discount still possible


def _anomaly_bounds(beliefs: Beliefs) -> tuple[float, float]:
    if not beliefs.recent_anomaly:
        return (0.0, 0.0)
    weight = WEIGHTS[ANOMALY]
    status = beliefs.facts.get(ANOMALY)
    if status is not None:
        term = weight * ANOMALY_MULT[status]
        return (term, term)
    if ANOMALY in beliefs.unresolvable:
        return (weight, weight)
    # A flagged UE's status is either still active or since resolved.
    return (weight * ANOMALY_MULT["resolved"], weight)


def risk_bounds(beliefs: Beliefs) -> tuple[float, float]:
    """(risk_min, risk_max) given what is known, unknown, and unanswerable."""
    terms = [
        _facet_bounds(beliefs, AUTH, LEVEL_RISK, TREND_AUTH),
        _facet_bounds(beliefs, PDU, LEVEL_RISK, None),
        _facet_bounds(beliefs, TRAFFIC, TRAFFIC_RISK, TREND_TRAFFIC),
        _anomaly_bounds(beliefs),
    ]
    behaviour = LABEL_RISK[beliefs.behaviour_label] * WEIGHTS["behaviour"]
    low = min(sum(t[0] for t in terms) + behaviour, 1.0)
    high = min(sum(t[1] for t in terms) + behaviour, 1.0)
    return (round(low, 4), round(high, 4))


def tier_for(risk: float) -> Tier:
    return risk_to_max_tier(risk)


@dataclass(frozen=True)
class Candidate:
    """A question worth asking, ranked by risk-interval width removed per point."""

    predicate: str
    args: dict[str, str]
    facet_key: str
    cost: int
    value: float


def _base_term(beliefs: Beliefs, facet: str, risk_map: dict[str, float]) -> float:
    value = beliefs.facts.get(facet)
    return 0.0 if value is None else risk_map[value] * WEIGHTS[facet]


def candidate_questions(
    beliefs: Beliefs, budget_remaining: int | None = None
) -> list[Candidate]:
    """Affordable, informative questions, best value-per-cost first.

    Pass ``budget_remaining=None`` to list every informative question
    regardless of affordability (used to distinguish "out of budget" from
    "nothing left worth asking").
    """
    candidates: list[Candidate] = []

    def unknown(key: str) -> bool:
        return key not in beliefs.facts and key not in beliefs.unresolvable

    for facet in (AUTH, PDU, TRAFFIC):
        if unknown(facet):
            candidates.append(Candidate(facet, {}, facet, COST[facet], WEIGHTS[facet]))

    if beliefs.recent_anomaly and unknown(ANOMALY):
        width = WEIGHTS[ANOMALY] * (1.0 - ANOMALY_MULT["resolved"])
        candidates.append(Candidate(ANOMALY, {}, ANOMALY, COST[ANOMALY], width))

    for facet, risk_map, trend_key, trend_facet in (
        (AUTH, LEVEL_RISK, TREND_AUTH, "auth_failures"),
        (TRAFFIC, TRAFFIC_RISK, TREND_TRAFFIC, "traffic_spikes"),
    ):
        base = _base_term(beliefs, facet, risk_map)
        if base > 0.0 and unknown(trend_key):
            candidates.append(Candidate(
                "trend", {"facet": trend_facet}, trend_key,
                COST["trend"], base * TREND_DISCOUNT,
            ))

    if budget_remaining is not None:
        candidates = [c for c in candidates if c.cost <= budget_remaining]

    return sorted(candidates, key=lambda c: (-c.value / c.cost, c.cost, c.facet_key))


def apply_negotiated_floor(
    tier: Tier, beliefs: Beliefs
) -> tuple[Tier, bool, str | None]:
    """The safety floor, evolved for negotiated facts.

    Unlike the one-shot floor, a flagged anomaly or an anomalous label stops
    capping the tier once the negotiation has established the anomaly is
    resolved — distinguishing stale trouble from live trouble is exactly what
    the follow-up questions are for. Unknown always fails closed.
    """
    status = beliefs.facts.get(ANOMALY)
    resolved = status in ("resolved", "none")
    floor = tier
    reason = None

    if beliefs.recent_anomaly and not resolved and TIER_ORDER[floor] > TIER_ORDER[Tier.T2_MONITORED_ACCESS]:
        floor = Tier.T2_MONITORED_ACCESS
        reason = "anomaly flag not established as resolved — clipped to T2"

    if beliefs.facts.get(AUTH) == "low" and TIER_ORDER[floor] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor = Tier.T1_RESTRICTED_ACCESS
        reason = "auth_stability=low forced clip to T1"

    if beliefs.behaviour_label == "anomalous" and not resolved and TIER_ORDER[floor] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor = Tier.T1_RESTRICTED_ACCESS
        reason = "behaviour_label=anomalous with unresolved anomaly — clipped to T1"

    clipped = floor != tier
    return floor, clipped, reason if clipped else None
