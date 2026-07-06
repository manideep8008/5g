"""In-process session client: Network B's decision agent driving Network A's
boundary directly, no HTTP.

Protocol-compatible with ``session_client.SessionClient`` (same methods,
same models, same None-on-failure contract). The full gate sequence —
grammar, budget, responders, verifier, transcript — runs for real; only the
transport and signing layers are skipped, and those are exercised by
tests_e2e. Each client instance carries its own requester_id so budget
sweeps get isolated ledger windows.
"""

from __future__ import annotations

from network_a.negotiation import boundary
from network_a.negotiation import schemas as a_schemas
from network_a.negotiation.session import SessionExpired, SessionNotFound
from network_b.contract import negotiation_schemas as b_schemas


class LocalClient:
    def __init__(self, requester_id: str = "network_b"):
        self.requester_id = requester_id

    async def open(
        self, req: b_schemas.SessionOpenRequest
    ) -> b_schemas.SessionOpenResponse | None:
        a_req = a_schemas.SessionOpenRequest.model_validate(
            {**req.model_dump(), "requester_id": self.requester_id}
        )
        try:
            resp = await boundary.open_session(a_req)
        except boundary.NoEvidence:
            return None
        return b_schemas.SessionOpenResponse.model_validate(resp.model_dump())

    async def query(
        self, req: b_schemas.QueryRequest
    ) -> b_schemas.QueryResponse | None:
        try:
            resp = await boundary.handle_query(
                a_schemas.QueryRequest.model_validate(req.model_dump())
            )
        except (SessionNotFound, SessionExpired):
            return None
        return b_schemas.QueryResponse.model_validate(resp.model_dump())

    async def close(
        self, req: b_schemas.CloseRequest
    ) -> b_schemas.CloseResponse | None:
        try:
            resp = await boundary.close_session(
                a_schemas.CloseRequest.model_validate(req.model_dump())
            )
        except SessionNotFound:
            return None
        return b_schemas.CloseResponse.model_validate(resp.model_dump())
