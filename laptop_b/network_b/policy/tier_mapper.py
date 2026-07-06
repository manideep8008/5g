"""Deprecated backward-compatibility wrapper for tier mapping.

All active policy logic has been consolidated into policy_engine.py.
Please import from network_b.policy.policy_engine directly.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "tier_mapper is deprecated; import from network_b.policy.policy_engine instead.",
    DeprecationWarning,
    stacklevel=2,
)

from network_b.policy.policy_engine import (
    apply_safety_floor,
    risk_to_max_tier,
)

__all__ = [
    "apply_safety_floor",
    "risk_to_max_tier",
]
