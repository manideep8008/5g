"""Signed HTTP client for Network A's attestation session endpoints.

Same trust posture as the one-shot ``fetch_summary``: every request is
HMAC-signed, every response signature is verified before the body is
trusted, and any failure — transport error, non-200, bad signature —
returns None so the caller fails closed.
"""

from __future__ import annotations

import logging
import os

import httpx
from pydantic import BaseModel

from network_b.contract import request_signer as rs
from network_b.contract.negotiation_schemas import (
    CloseRequest,
    CloseResponse,
    QueryRequest,
    QueryResponse,
    SessionOpenRequest,
    SessionOpenResponse,
)

logger = logging.getLogger(__name__)

SESSION_PATH = "/v1/attestation/session"
QUERY_PATH = "/v1/attestation/query"
CLOSE_PATH = "/v1/attestation/close"

_DEFAULT_NETWORK_A_URL = "http://localhost:8001"
_TIMEOUT_SEC = 10.0


class SessionClient:
    def __init__(
        self,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        self.base_url = base_url or os.environ.get("NETWORK_A_URL", _DEFAULT_NETWORK_A_URL)
        self._client = client
        self._response_nonces = rs.NonceCache()

    async def _post(
        self, path: str, payload: BaseModel, response_model: type[BaseModel]
    ) -> BaseModel | None:
        body = rs.canonical_body(payload.model_dump(mode="json"))
        headers = {**rs.sign("POST", path, body), "content-type": "application/json"}

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=_TIMEOUT_SEC)
        try:
            resp = await client.post(f"{self.base_url}{path}", content=body, headers=headers)
            if resp.status_code != 200:
                logger.info("%s returned %d: %s", path, resp.status_code, resp.text)
                return None

            if rs.signing_required():
                try:
                    rs.verify(
                        "POST", path, resp.content, resp.headers,
                        nonce_cache=self._response_nonces,
                    )
                except rs.SignatureError as exc:
                    logger.warning(
                        "rejecting %s response — bad signature: %s", path, exc
                    )
                    return None

            return response_model.model_validate(resp.json())
        except httpx.HTTPError as exc:
            logger.warning("negotiation call %s failed: %s", path, exc)
            return None
        finally:
            if owns_client:
                await client.aclose()

    async def open(self, req: SessionOpenRequest) -> SessionOpenResponse | None:
        return await self._post(SESSION_PATH, req, SessionOpenResponse)

    async def query(self, req: QueryRequest) -> QueryResponse | None:
        return await self._post(QUERY_PATH, req, QueryResponse)

    async def close(self, req: CloseRequest) -> CloseResponse | None:
        return await self._post(CLOSE_PATH, req, CloseResponse)
