"""Tests for llm_client — response parsing, prompt building, error handling."""

import pytest

from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import (
    build_user_prompt,
    parse_llm_response,
)


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


class TestParseLlmResponse:
    def test_valid_json(self):
        raw = '{"proposed_tier": "T3_FULL_ACCESS", "reasoning": "All stable.", "confidence": 0.95}'
        result = parse_llm_response(raw)
        assert result is not None
        assert result.proposed_tier == Tier.T3_FULL_ACCESS
        assert result.reasoning == "All stable."
        assert result.confidence == 0.95

    def test_valid_json_t0(self):
        raw = '{"proposed_tier": "T0_REJECT", "reasoning": "Anomalous.", "confidence": 0.8}'
        result = parse_llm_response(raw)
        assert result.proposed_tier == Tier.T0_REJECT

    def test_valid_json_t1(self):
        raw = '{"proposed_tier": "T1_RESTRICTED_ACCESS", "reasoning": "High risk.", "confidence": 0.7}'
        result = parse_llm_response(raw)
        assert result.proposed_tier == Tier.T1_RESTRICTED_ACCESS

    def test_valid_json_t2(self):
        raw = '{"proposed_tier": "T2_MONITORED_ACCESS", "reasoning": "Some concern.", "confidence": 0.6}'
        result = parse_llm_response(raw)
        assert result.proposed_tier == Tier.T2_MONITORED_ACCESS

    def test_json_with_surrounding_text(self):
        raw = 'Here is my decision:\n{"proposed_tier": "T3_FULL_ACCESS", "reasoning": "OK.", "confidence": 0.9}\nDone.'
        result = parse_llm_response(raw)
        assert result is not None
        assert result.proposed_tier == Tier.T3_FULL_ACCESS

    def test_invalid_tier_returns_none(self):
        raw = '{"proposed_tier": "T5_SUPER_ACCESS", "reasoning": "??", "confidence": 0.5}'
        result = parse_llm_response(raw)
        assert result is None

    def test_empty_string_returns_none(self):
        result = parse_llm_response("")
        assert result is None

    def test_garbage_returns_none(self):
        result = parse_llm_response("this is not json at all")
        assert result is None

    def test_missing_tier_returns_none(self):
        raw = '{"reasoning": "No tier field.", "confidence": 0.5}'
        result = parse_llm_response(raw)
        assert result is None

    def test_confidence_clamped_high(self):
        raw = '{"proposed_tier": "T3_FULL_ACCESS", "reasoning": "Sure.", "confidence": 1.5}'
        result = parse_llm_response(raw)
        assert result.confidence == 1.0

    def test_confidence_clamped_low(self):
        raw = '{"proposed_tier": "T3_FULL_ACCESS", "reasoning": "Sure.", "confidence": -0.5}'
        result = parse_llm_response(raw)
        assert result.confidence == 0.0

    def test_missing_confidence_defaults(self):
        raw = '{"proposed_tier": "T2_MONITORED_ACCESS", "reasoning": "Caution."}'
        result = parse_llm_response(raw)
        assert result.confidence == 0.5

    def test_preserves_raw_response(self):
        raw = '{"proposed_tier": "T3_FULL_ACCESS", "reasoning": "OK.", "confidence": 0.9}'
        result = parse_llm_response(raw)
        assert result.raw_response == raw


class TestBuildUserPrompt:
    def test_contains_all_fields(self):
        summary = _make_summary()
        prompt = build_user_prompt(summary)
        assert "auth_stability: high" in prompt
        assert "pdu_session_stability: high" in prompt
        assert "traffic_pattern: stable" in prompt
        assert "recent_anomaly: false" in prompt
        assert "behaviour_label: normal" in prompt
        assert "eMBB" in prompt

    def test_anomaly_shows_true(self):
        summary = _make_summary(recent_anomaly=True)
        prompt = build_user_prompt(summary)
        assert "recent_anomaly: true" in prompt

    def test_custom_slice_and_service(self):
        summary = _make_summary()
        prompt = build_user_prompt(summary, requested_slice="URLLC", requested_service="iot")
        assert "slice=URLLC" in prompt
        assert "service=iot" in prompt

    def test_multiple_slices(self):
        summary = _make_summary(known_slice_usage=["eMBB", "URLLC"])
        prompt = build_user_prompt(summary)
        assert "eMBB, URLLC" in prompt
