"""Deprecated backward-compatibility wrapper for compute_risk_score.

All active policy logic has been consolidated into policy_engine.py.
Please import from network_b.policy.policy_engine directly.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "risk_score is deprecated; import from network_b.policy.policy_engine instead.",
    DeprecationWarning,
    stacklevel=2,
)

from network_b.policy.policy_engine import (
    DEFAULT_WEIGHTS,
    FIELD_RISK_MAP,
    compute_risk_score,
)

__all__ = [
    "DEFAULT_WEIGHTS",
    "FIELD_RISK_MAP",
    "compute_risk_score",
]
