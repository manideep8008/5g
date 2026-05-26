"""Deprecated backward-compatibility wrapper for profile building.

All active summary logic has been consolidated into summary_generator.py.
Please import from network_a.summary.summary_generator directly.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "profile_builder is deprecated; import from network_a.summary.summary_generator instead.",
    DeprecationWarning,
    stacklevel=2,
)

from network_a.summary.summary_generator import (
    UeProfile,
    build_profile,
)

__all__ = [
    "UeProfile",
    "build_profile",
]
