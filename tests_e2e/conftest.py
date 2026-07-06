"""End-to-end suite: composes both laptops' packages in one process.

The two-laptop distribution keeps network_a and network_b in separate
project roots; this conftest puts both on sys.path so an E2E test can mount
Network A's real FastAPI app and drive Network B's real decision service
against it. Run from the dist root:

    python3 -m pytest tests_e2e
"""

import sys
from pathlib import Path

_DIST_ROOT = Path(__file__).resolve().parent.parent

for _root in (_DIST_ROOT, _DIST_ROOT / "laptop_a", _DIST_ROOT / "laptop_b"):
    path = str(_root)
    if path not in sys.path:
        sys.path.insert(0, path)
