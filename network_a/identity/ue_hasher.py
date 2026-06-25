"""Deprecated backward-compatibility wrapper for IMSI hashing.

All active identity logic has been consolidated into identity_mapper.py.
Please import from network_a.identity.identity_mapper directly.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "ue_hasher is deprecated; import from network_a.identity.identity_mapper instead.",
    DeprecationWarning,
    stacklevel=2,
)

from network_a.identity.identity_mapper import (
    pseudonymise_imsi,
    verify_pseudonym,
)

__all__ = [
    "pseudonymise_imsi",
    "verify_pseudonym",
]
