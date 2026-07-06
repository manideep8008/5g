"""Tests for the temporal timeline view over UE sessions."""

from datetime import datetime, timedelta, timezone

import pytest

from network_a import db
from network_a.summary.timeline import build_timeline

UE = "UE_HASH_TEST"
BASE = datetime(2026, 7, 6, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


async def seed_sessions(failures_per_session: list[int], spikes_per_session: list[int]):
    for i, (failures, spikes) in enumerate(zip(failures_per_session, spikes_per_session)):
        await db.insert_session(
            pseudonym=UE,
            started_at=BASE + timedelta(hours=i),
            auth_attempts=5,
            auth_failures=failures,
            pdu_attempts=3,
            pdu_failures=0,
            spike_count=spikes,
        )


@pytest.mark.asyncio
async def test_no_sessions_returns_none():
    assert await build_timeline(UE) is None


@pytest.mark.asyncio
async def test_halves_split_oldest_first():
    await seed_sessions([2, 2, 0, 0], [1, 1, 0, 0])
    older, recent = await build_timeline(UE, buckets=2)

    assert older.session_count == 2
    assert older.auth_failure_rate == pytest.approx(0.4)
    assert older.spike_rate == pytest.approx(1.0)
    assert recent.auth_failure_rate == pytest.approx(0.0)
    assert recent.spike_rate == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_bucket_totals_match_whole_window():
    await seed_sessions([1, 0, 2, 1], [0, 1, 0, 1])
    buckets = await build_timeline(UE, buckets=2)

    assert sum(b.auth_failures for b in buckets) == 4
    assert sum(b.spike_count for b in buckets) == 2
    assert sum(b.session_count for b in buckets) == 4


@pytest.mark.asyncio
async def test_odd_session_count_still_covers_all_sessions():
    await seed_sessions([1, 1, 1, 1, 1], [0, 0, 0, 0, 0])
    buckets = await build_timeline(UE, buckets=2)
    assert sum(b.session_count for b in buckets) == 5


@pytest.mark.asyncio
async def test_single_session_yields_empty_older_half():
    await seed_sessions([1], [0])
    older, recent = await build_timeline(UE, buckets=2)

    assert older.session_count == 0
    assert older.auth_failure_rate is None
    assert recent.session_count == 1


@pytest.mark.asyncio
async def test_rate_is_none_when_no_attempts():
    await db.insert_session(
        pseudonym=UE,
        started_at=BASE,
        auth_attempts=0,
        auth_failures=0,
    )
    buckets = await build_timeline(UE, buckets=1)
    assert buckets[0].auth_failure_rate is None
