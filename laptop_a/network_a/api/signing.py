"""FastAPI glue for the HMAC signing layer on Network A.

Network A is the *provider*: it verifies inbound summary requests from
Network B and signs its own responses so B can confirm provenance. The raw
crypto lives in ``network_a.contract.request_signer``; this module only adapts
it to Starlette request/response objects.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, Response

from network_a.contract import request_signer as rs

# One process-wide replay cache for inbound requests.
_INBOUND_NONCES = rs.NonceCache()


async def require_signed_request(request: Request) -> None:
    """Dependency: reject unsigned/invalid/expired/replayed requests with 401.

    Honours ``REQUIRE_SIGNED_REQUESTS`` — when disabled the request passes
    through unverified (rollout escape hatch). Default is fail-closed.
    """

    #check if the signing is required, if not then return default true. in development we can put these false.
    if not rs.signing_required():
        return

    #this is getting the body of the request
    body = await request.body()
    try:
        #this is verifying the signature of the request
        rs.verify(
            request.method,
            request.url.path,
            body,
            request.headers,
            nonce_cache=_INBOUND_NONCES,
        )
    except rs.SignatureError as exc:
        raise HTTPException(status_code=401, detail=f"invalid request signature: {exc}")


def signed_json_response(method: str, path: str, payload: dict) -> Response:
    """Serialise ``payload`` to canonical JSON and attach a fresh signature."""
    body = rs.canonical_body(payload)
    headers = rs.sign(method, path, body)
    return Response(content=body, media_type="application/json", headers=headers)
