"""Tests for oracle generation and evaluation pipeline."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from experiments.generate_oracle import (
    generate_adversarial_scenarios,
    generate_conflicting_scenarios,
    generate_oracle_dataset,
    generate_unambiguous_scenarios,
)
from experiments.generate_results import (
    compute_accuracy,
    compute_confusion_matrix,
    compute_injection_stats,
    compute_latency_stats,
    compute_severity_weighted_error,
)
from experiments.run_scenario_experiments import (
    run_all_experiments,
    run_rule_without_summary,
    _make_access_request,
    _make_summary,
)
from network_a.summary.summary_schema import Tier


class TestOracleGeneration:
    def test_unambiguous_count(self):
        scenarios = generate_unambiguous_scenarios()
        assert len(scenarios) >= 40

    def test_conflicting_count(self):
        scenarios = generate_conflicting_scenarios()
        assert len(scenarios) == 15

    def test_adversarial_count(self):
        scenarios = generate_adversarial_scenarios()
        assert len(scenarios) == 5

    def test_full_dataset_structure(self):
        dataset = generate_oracle_dataset()
        assert len(dataset) >= 60

        for scenario in dataset:
            assert "scenario_id" in scenario
            assert "category" in scenario
            assert "summary" in scenario
            assert "expected_tier" in scenario
            assert "reasoning" in scenario
            assert "difficulty" in scenario

    def test_all_tiers_represented(self):
        dataset = generate_oracle_dataset()
        tiers = {s["expected_tier"] for s in dataset}
        assert "T0_REJECT" in tiers
        assert "T1_RESTRICTED_ACCESS" in tiers
        assert "T2_MONITORED_ACCESS" in tiers
        assert "T3_FULL_ACCESS" in tiers

    def test_categories_valid(self):
        dataset = generate_oracle_dataset()
        for s in dataset:
            assert s["category"] in ("unambiguous", "conflicting", "adversarial")

    def test_adversarial_never_expects_t3(self):
        scenarios = generate_adversarial_scenarios()
        for s in scenarios:
            assert s.expected_tier != "T3_FULL_ACCESS"

    def test_scenario_ids_unique(self):
        dataset = generate_oracle_dataset()
        ids = [s["scenario_id"] for s in dataset]
        assert len(ids) == len(set(ids))

    def test_summary_fields_valid(self):
        dataset = generate_oracle_dataset()
        valid_auth = {"high", "medium", "low"}
        valid_pdu = {"high", "medium", "low"}
        valid_traffic = {"stable", "moderate", "volatile"}
        valid_behaviour = {"normal", "suspicious", "anomalous"}

        for s in dataset:
            summary = s["summary"]
            assert summary["auth_stability"] in valid_auth
            assert summary["pdu_session_stability"] in valid_pdu
            assert summary["traffic_pattern"] in valid_traffic
            assert isinstance(summary["recent_anomaly"], bool)
            assert summary["behaviour_label"] in valid_behaviour


class TestExperimentRunner:
    def test_rule_without_summary_deterministic(self):
        req = _make_access_request("TEST-001")
        tier1, risk1, _, _ = run_rule_without_summary(req)
        tier2, risk2, _, _ = run_rule_without_summary(req)
        assert tier1 == tier2
        assert risk1 == risk2

    def test_rule_without_summary_never_t3(self):
        req = _make_access_request("TEST-002")
        tier, _, _, _ = run_rule_without_summary(req)
        assert tier != "T3_FULL_ACCESS"

    @pytest.mark.asyncio
    async def test_run_all_no_llm(self):
        dataset = generate_oracle_dataset()
        oracle_path = Path("/tmp/test_oracle.json")
        oracle_path.write_text(json.dumps(dataset[:5]))

        results = await run_all_experiments(
            oracle_path=oracle_path,
            seeds=1,
            use_llm=False,
        )

        assert len(results) == 15  # 5 scenarios × 3 systems × 1 seed
        for r in results:
            assert r["system"] in ("full", "rule_without_summary", "single_llm")
            assert r["predicted_tier"] in [t.value for t in Tier]
            assert r["expected_tier"] in [t.value for t in Tier]
            assert isinstance(r["correct"], bool)
            assert isinstance(r["latency_ms"], float)

        oracle_path.unlink()


class TestResultsGenerator:
    @pytest.fixture
    def sample_results(self):
        return [
            {"system": "full", "predicted_tier": "T3_FULL_ACCESS", "expected_tier": "T3_FULL_ACCESS", "correct": True, "category": "unambiguous", "latency_ms": 1.0, "scenario_id": "S1"},
            {"system": "full", "predicted_tier": "T2_MONITORED_ACCESS", "expected_tier": "T2_MONITORED_ACCESS", "correct": True, "category": "unambiguous", "latency_ms": 2.0, "scenario_id": "S2"},
            {"system": "full", "predicted_tier": "T2_MONITORED_ACCESS", "expected_tier": "T1_RESTRICTED_ACCESS", "correct": False, "category": "adversarial", "latency_ms": 50.0, "scenario_id": "S3"},
            {"system": "rule_without_summary", "predicted_tier": "T2_MONITORED_ACCESS", "expected_tier": "T3_FULL_ACCESS", "correct": False, "category": "unambiguous", "latency_ms": 0.1, "scenario_id": "S1"},
            {"system": "rule_without_summary", "predicted_tier": "T2_MONITORED_ACCESS", "expected_tier": "T2_MONITORED_ACCESS", "correct": True, "category": "unambiguous", "latency_ms": 0.1, "scenario_id": "S2"},
            {"system": "rule_without_summary", "predicted_tier": "T2_MONITORED_ACCESS", "expected_tier": "T0_REJECT", "correct": False, "category": "adversarial", "latency_ms": 0.1, "scenario_id": "S3"},
        ]

    def test_accuracy(self, sample_results):
        acc = compute_accuracy(sample_results)
        assert acc["full"]["overall_accuracy"] == pytest.approx(2 / 3, abs=0.01)
        assert acc["rule_without_summary"]["overall_accuracy"] == pytest.approx(1 / 3, abs=0.01)

    def test_confusion_matrix_shape(self, sample_results):
        matrices = compute_confusion_matrix(sample_results)
        for sys_name, data in matrices.items():
            assert len(data["matrix"]) == 4
            for row in data["matrix"]:
                assert len(row) == 4

    def test_severity_weighted_error(self, sample_results):
        severity = compute_severity_weighted_error(sample_results)
        assert severity["full"]["mean_penalty"] < severity["rule_without_summary"]["mean_penalty"]

    def test_latency_stats(self, sample_results):
        latency = compute_latency_stats(sample_results)
        assert latency["full"]["mean_ms"] > 0
        assert latency["full"]["p50_ms"] >= latency["full"]["min_ms"]

    def test_injection_stats(self, sample_results):
        injection = compute_injection_stats(sample_results)
        assert injection["full"]["total_adversarial_runs"] == 1
        assert injection["full"]["t3_granted_count"] == 0
        assert injection["full"]["injection_success_rate"] == 0.0
        assert injection["rule_without_summary"]["t3_granted_count"] == 0
