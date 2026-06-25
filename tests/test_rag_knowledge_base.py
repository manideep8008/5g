from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from network_b.rag.knowledge_base import (
    load_kb_documents,
    load_policy_documents,
    load_precedent_documents,
    load_principle_documents,
)


@pytest.fixture()
def policy_yaml(tmp_path: Path) -> Path:
    policy = {
        "risk_weights": {"auth_stability": 0.25, "recent_anomaly": 0.20},
        "tier_thresholds": {
            "T3_FULL_ACCESS": {"max_risk": 0.20},
            "T0_REJECT": {"min_risk": 0.80},
        },
        "safety_floor": {
            "enabled": True,
            "hard_rules": [
                {"condition": "recent_anomaly == true", "max_tier": "T2_MONITORED_ACCESS"},
                {"condition": "auth_stability == 'low'", "max_tier": "T1_RESTRICTED_ACCESS"},
            ],
        },
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    return path


@pytest.fixture()
def seed_docs_dir(tmp_path: Path) -> Path:
    d = tmp_path / "seed_docs"
    d.mkdir()
    (d / "principles.md").write_text(
        "# Zero Trust Principles\n\n"
        "Intro paragraph.\n\n"
        "## Never trust by default\n\n"
        "Every request is verified.\n\n"
        "## Verify with current evidence\n\n"
        "Use the freshest summary.\n"
    )
    return d


@pytest.fixture()
def access_decisions_dir(tmp_path: Path) -> Path:
    d = tmp_path / "decisions"
    d.mkdir()
    decision = {
        "request_id": "REQ-001",
        "ue_pseudonym": "UE_HASH_AAA",
        "final_tier": "T2_MONITORED_ACCESS",
        "risk_score": 0.42,
        "reason": "Single anomaly flag",
        "policy_engine_metadata": {
            "llm_model_id": "rules_only",
            "deterministic_max_tier": "T2_MONITORED_ACCESS",
            "safety_floor_clipped": True,
        },
        "simulated_enforcement": {"allowed_services": ["standard_data"]},
        "decided_at": "2026-05-01T12:00:00+00:00",
        "summary": {
            "auth_stability": "high",
            "pdu_session_stability": "high",
            "traffic_pattern": "stable",
            "known_slice_usage": ["eMBB"],
            "recent_anomaly": True,
            "behaviour_label": "normal",
        },
    }
    (d / "REQ-001.json").write_text(json.dumps(decision))

    no_summary = dict(decision)
    no_summary["request_id"] = "REQ-002"
    no_summary.pop("summary")
    (d / "REQ-002.json").write_text(json.dumps(no_summary))
    return d


@pytest.mark.unit
class TestPolicyLoader:
    def test_extracts_risk_thresholds_and_floor(self, policy_yaml):
        docs = load_policy_documents(policy_yaml)
        kinds = {d.source_title for d in docs}
        assert "Risk weights" in kinds
        assert "Tier thresholds" in kinds
        # Two hard rules → two safety-floor docs.
        floor_docs = [d for d in docs if "Safety floor" in d.source_title]
        assert len(floor_docs) == 2
        assert all(d.source_type == "policy" for d in docs)

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_policy_documents(tmp_path / "missing.yaml") == []


@pytest.mark.unit
class TestPrincipleLoader:
    def test_splits_markdown_by_h2(self, seed_docs_dir):
        docs = load_principle_documents(seed_docs_dir)
        titles = sorted(d.source_title for d in docs)
        assert "Never trust by default" in titles
        assert "Verify with current evidence" in titles
        assert all(d.source_type == "principle" for d in docs)

    def test_missing_dir_returns_empty(self, tmp_path):
        assert load_principle_documents(tmp_path / "absent") == []


@pytest.mark.unit
class TestPrecedentLoader:
    def test_skips_decisions_without_summary(self, access_decisions_dir):
        docs = load_precedent_documents(
            access_decisions_dir, max_count=10, max_age_days=3650
        )
        assert len(docs) == 1
        assert docs[0].metadata["request_id"] == "REQ-001"
        assert "T2_MONITORED_ACCESS" in docs[0].content

    def test_age_cutoff_drops_old_decisions(self, access_decisions_dir):
        docs = load_precedent_documents(
            access_decisions_dir, max_count=10, max_age_days=1
        )
        # decided_at is 2026-05-01 — far older than 1 day.
        assert docs == []

    def test_missing_dir_returns_empty(self, tmp_path):
        assert load_precedent_documents(
            tmp_path / "absent", max_count=10, max_age_days=30
        ) == []


@pytest.mark.unit
class TestLoadAll:
    def test_combines_all_sources(self, policy_yaml, seed_docs_dir, access_decisions_dir):
        docs = load_kb_documents(
            policy_yaml=policy_yaml,
            seed_docs_dir=seed_docs_dir,
            access_decisions_dir=access_decisions_dir,
            max_precedents=10,
            max_precedent_age_days=3650,
        )
        types = {d.source_type for d in docs}
        assert types == {"policy", "principle", "precedent"}
