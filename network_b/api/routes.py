from datetime import datetime, timezone

from fastapi import APIRouter

from network_a.summary.summary_schema import AccessDecision, AccessRequest
from network_b.decision.decision_service import handle_access_request

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "network_b", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.post("/access/request", response_model=AccessDecision)
async def request_access(req: AccessRequest):
    return await handle_access_request(req)
