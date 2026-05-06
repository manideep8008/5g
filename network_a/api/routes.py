from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from network_a.summary.summary_generator import generate_summary
from network_a.summary.summary_schema import SummaryRequest, SummaryResponse

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "network_a", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.post("/summary/request", response_model=SummaryResponse)
async def request_summary(req: SummaryRequest):
    try:
        response = await generate_summary(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if response is None:
        raise HTTPException(status_code=404, detail=f"No summary available for {req.ue_pseudonym}")

    return response
