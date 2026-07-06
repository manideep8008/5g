"""Tests pinning the demo-critical properties of the seeded scenarios.

The negotiation demo depends on these shapes: the recovering UE must be
indistinguishable from a troubled UE in the flat summary, and distinguishable
in the timeline. If a seed change breaks that, the demo story breaks with it.
"""

import pytest

from network_a import db
from network_a.api.routes import seed_scenarios
from network_a.summary.summary_generator import build_profile, generate_behavioural_summary
from network_a.summary.summary_schema import BehaviourLabel
from network_a.summary.timeline import build_timeline


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


async def summary_for(pseudonym: str):
    profile = await build_profile(pseudonym)
    return generate_behavioural_summary(profile)


@pytest.mark.asyncio
async def test_seeds_all_four_scenarios():
    result = await seed_scenarios()
    pseudonyms = {r["pseudonym"] for r in result["seeded"]}
    assert pseudonyms == {
        "UE_SIM_NORMAL",
        "UE_SIM_SUSPICIOUS",
        "UE_SIM_RECOVERING",
        "UE_SIM_ANOMALOUS",
    }


@pytest.mark.asyncio
async def test_normal_ue_classifies_normal():
    await seed_scenarios()
    summary = await summary_for("UE_SIM_NORMAL")
    assert summary.behaviour_label == BehaviourLabel.NORMAL
    assert summary.recent_anomaly is False


@pytest.mark.asyncio
async def test_suspicious_ue_classifies_suspicious():
    await seed_scenarios()
    summary = await summary_for("UE_SIM_SUSPICIOUS")
    assert summary.behaviour_label == BehaviourLabel.SUSPICIOUS
    assert summary.recent_anomaly is True


@pytest.mark.asyncio
async def test_anomalous_ue_classifies_anomalous():
    await seed_scenarios()
    summary = await summary_for("UE_SIM_ANOMALOUS")
    assert summary.behaviour_label == BehaviourLabel.ANOMALOUS


@pytest.mark.asyncio
async def test_recovering_ue_looks_troubled_in_flat_summary():
    """The fixed-attestation path must NOT be able to see the recovery."""
    await seed_scenarios()
    summary = await summary_for("UE_SIM_RECOVERING")
    assert summary.behaviour_label == BehaviourLabel.ANOMALOUS
    assert summary.recent_anomaly is True


@pytest.mark.asyncio
async def test_recovering_ue_is_clean_in_recent_half():
    """The timeline is what makes the recovery visible to the trend agent."""
    await seed_scenarios()
    older, recent = await build_timeline("UE_SIM_RECOVERING", buckets=2)

    assert older.auth_failure_rate == pytest.approx(0.4)
    assert older.spike_count > 0
    assert recent.auth_failure_rate == pytest.approx(0.0)
    assert recent.spike_count == 0


@pytest.mark.asyncio
async def test_suspicious_ue_trouble_is_steady():
    """Contrast case: the suspicious UE must NOT look like it recovered."""
    await seed_scenarios()
    older, recent = await build_timeline("UE_SIM_SUSPICIOUS", buckets=2)

    assert recent.auth_failure_rate == pytest.approx(older.auth_failure_rate)
    assert recent.spike_count > 0
