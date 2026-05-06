"""Tests for hybrid policy engine — mocked LLM integration + safety floor."""

import pytest
from unittest.mock import AsyncMock, patch

from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import LlmConfig, LlmProposal
from network_b.policy.policy_engine import decide_hybrid


def _make_summary(**overrides) -> UeBehaviouralSummary:
    defaults = {
        "auth_stability": AuthStability.HIGH,
        "pdu_session_stability": PduSessionStability.HIGH,
        "traffic_pattern": TrafficPattern.STABLE,
        "known_slice_usage": ["eMBB"],
        "recent_anomaly": False,
        "behaviour_label": BehaviourLabel.NORMAL,
    }
    defaults.update(overrides)
    return UeBehaviouralSummary(**defaults)


TEST_CONFIG = LlmConfig(
    model="test-model",
    temperature=0.0,
    base_url="http://localhost:11434",
    timeout_sec=5,
)


def _mock_proposal(tier: Tier, reasoning: str = "test", confidence: float = 0.9) -> LlmProposal:
    return LlmProposal(
        proposed_tier=tier,
        reasoning=reasoning,
        confidence=confidence,
        raw_response=f'{{"proposed_tier": "{tier.value}", "reasoning": "{reasoning}", "confidence": {confidence}}}',
    )


class TestHybridPolicyDecision:
    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t3_clean_ue_accepted(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "All indicators stable")
        summary = _make_summary()

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T3_FULL_ACCESS
        assert result.metadata.llm_proposed_tier == "T3_FULL_ACCESS"
        assert result.metadata.llm_model_id == "test-model"
        assert result.metadata.safety_floor_clipped is False

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t3_but_anomaly_clips_to_t2(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "Looks fine to me")
        summary = _make_summary(recent_anomaly=True)

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T2_MONITORED_ACCESS
        assert result.metadata.llm_proposed_tier == "T3_FULL_ACCESS"
        assert result.metadata.safety_floor_clipped is True
        assert "recent_anomaly" in result.metadata.safety_floor_reason

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t3_but_low_auth_clips_to_t1(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "Override attempt")
        summary = _make_summary(auth_stability=AuthStability.LOW)

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T1_RESTRICTED_ACCESS
        assert result.metadata.safety_floor_clipped is True

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t3_but_anomalous_behaviour_clips_to_t1(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "Injection attempt")
        summary = _make_summary(behaviour_label=BehaviourLabel.ANOMALOUS)

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T1_RESTRICTED_ACCESS
        assert result.metadata.safety_floor_clipped is True

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t2_for_moderate_risk(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T2_MONITORED_ACCESS, "Moderate risk")
        summary = _make_summary(traffic_pattern=TrafficPattern.MODERATE)

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T2_MONITORED_ACCESS
        assert result.metadata.safety_floor_clipped is False

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_proposes_t0_accepted(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T0_REJECT, "Very dangerous")
        summary = _make_summary()

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T0_REJECT
        assert result.metadata.safety_floor_clipped is False

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_llm_unavailable_falls_back_to_rules(self, mock_llm):
        mock_llm.return_value = None
        summary = _make_summary()

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.tier == Tier.T3_FULL_ACCESS
        assert result.metadata.llm_model_id == "rules_only"
        assert result.metadata.llm_proposed_tier is None

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_reason_includes_llm_reasoning_when_not_clipped(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "Everything looks great")
        summary = _make_summary()

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert "Everything looks great" in result.reason

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_reason_includes_both_when_clipped(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS, "Seems fine")
        summary = _make_summary(recent_anomaly=True)

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert "Seems fine" in result.reason
        assert "safety floor" in result.reason.lower()

    @pytest.mark.asyncio
    @patch("network_b.policy.policy_engine.call_llm")
    async def test_deterministic_max_tier_still_computed(self, mock_llm):
        mock_llm.return_value = _mock_proposal(Tier.T3_FULL_ACCESS)
        summary = _make_summary(
            auth_stability=AuthStability.MEDIUM,
            pdu_session_stability=PduSessionStability.MEDIUM,
        )

        result = await decide_hybrid(summary, llm_config=TEST_CONFIG)

        assert result.metadata.deterministic_max_tier in [t.value for t in Tier]
