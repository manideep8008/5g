"""Evaluation harness: the privacy–utility frontier of negotiated attestation.

Generates a synthetic UE corpus with ground-truth tiers known by
construction, replays every scenario through both the fixed one-shot summary
path and the negotiated path across a sweep of privacy budgets, and emits
the CSVs and figures for the evaluation chapter. One command regenerates
everything:

    python3 -m evaluation.run

Like tests_e2e, this package composes both laptops' code in one process.
"""

import sys
from pathlib import Path

_DIST_ROOT = Path(__file__).resolve().parent.parent

for _laptop in ("laptop_a", "laptop_b"):
    _path = str(_DIST_ROOT / _laptop)
    if _path not in sys.path:
        sys.path.insert(0, _path)
