"""Deprecated backward-compatibility wrapper for behavioural summary mapping.

All active summary logic has been consolidated into summary_generator.py.
Please import from network_a.summary.summary_generator directly.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "risk_flag_generator is deprecated; import from network_a.summary.summary_generator instead.",
    DeprecationWarning,
    stacklevel=2,
)

from network_a.summary.summary_generator import (
    BucketThresholds,
    classify_auth_stability,
    classify_behaviour_label,
    classify_pdu_stability,
    classify_traffic_pattern,
    compute_overall_risk,
    generate_behavioural_summary,
    get_thresholds,
)

__all__ = [
    "BucketThresholds",
    "classify_auth_stability",
    "classify_behaviour_label",
    "classify_pdu_stability",
    "classify_traffic_pattern",
    "compute_overall_risk",
    "generate_behavioural_summary",
    "get_thresholds",
]
