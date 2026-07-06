import json
import os
from pathlib import Path

from network_b.contract.summary_schema import AccessDecision

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "access_decisions"


def log_decision(decision: AccessDecision) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{decision.request_id}_{decision.ue_pseudonym}.json"
    path = DATA_DIR / filename
    path.write_text(json.dumps(decision.model_dump(mode="json"), indent=2, default=str))
    return path
