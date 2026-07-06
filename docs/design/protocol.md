# Negotiated attestation protocol

Version 1 — session lifecycle, wire contract, and failure semantics for the
negotiation between Network B (deciding domain) and Network A (sensing
domain). The question grammar and budget it enforces are defined in
[grammar.md](grammar.md).

## Roles

- **Network B drives**: its decision agent chooses which questions to ask
  and when to stop. Action space: `ask(predicate, args)` or `decide(tier)`.
- **Network A controls the boundary**: every query passes signature,
  grammar, and budget checks before any responder agent runs, and every
  answer passes grounding verification and egress validation before it is
  signed and returned.

Neither side trusts the channel: every turn in both directions is signed
with the existing HMAC-SHA256 scheme (`X-Sig-*` headers, nonce replay cache,
5-minute clock skew), identical to the current one-shot summary endpoint.

## Endpoints

All served by Network A, all requiring signed requests, all returning
signed responses.

### POST /v1/attestation/session

Opens a negotiation session for one access decision.

Request: `{ request_id, ue_pseudonym, requester_id, context: { requested_slice, requested_dnn, requested_service } }`

Response:

    {
      "session_id": "...",
      "grammar_version": 1,
      "minimal_attestation": {
        "behaviour_label": "normal | suspicious | anomalous",
        "recent_anomaly": true,
        "recommendation": "T0..T3",
        "confidence": 0.0
      },
      "budget_total": 100,
      "budget_remaining": 100
    }

The minimal attestation is free (cost 0). The UE profile is snapshotted at
open; all answers in the session are computed from that snapshot.
Unknown pseudonym → 404, which Network B treats as the existing
no-summary path (fail closed to T1).

### POST /v1/attestation/query

Request: `{ "session_id": "...", "predicate": "trend", "args": { "facet": "auth_failures" } }`

Response (success):

    { "status": "answered", "answer": "decreasing",
      "cost": 10, "budget_remaining": 90, "grounded": true }

Response (no debit in any of these):

    { "status": "rejected",  "reason": "off_grammar", "budget_remaining": 90 }
    { "status": "refused",   "reason": "budget_exhausted", "budget_remaining": 5 }
    { "status": "unavailable", "reason": "insufficient_data", "budget_remaining": 90 }

### POST /v1/attestation/close

Request: `{ "session_id": "...", "final_tier": "T2_MONITORED_ACCESS" }`

Response: `{ "transcript_hash": "..." }`

Sealing writes the transcript (ordered signed Q/A pairs plus the final
tier) to durable storage and retires the session id.

## Session state machine

    OPEN ──query──▶ VALIDATING ──ok──▶ ANSWERING ──▶ OPEN          (budget > 0)
      │                 │ reject                │
      │                 ▼                       ▼
      │           (no debit, log)         budget ≤ 0 ─▶ EXHAUSTED
      └── close / idle timeout / max turns ───────────▶ CLOSED

- **VALIDATING** runs signature → grammar → budget, in that order, before
  any responder agent touches evidence. A rejected query exits here.
- **EXHAUSTED** answers every further query with `budget_exhausted`; the
  session stays open until `close` so the final decision lands on the
  transcript.
- **CLOSED** is terminal: transcript sealed, session id never reused.
- Limits: max 12 query turns, 120 s idle timeout. Both close the session;
  Network B decides with what it has.

## Gate order in /query (normative)

1. Signature + nonce + skew check (reject → HTTP 401, no state change)
2. Session state check (unknown/closed id → 404)
3. Grammar validation (fail → `rejected`, **no debit**, logged as probing)
4. Budget check (insufficient → `refused/budget_exhausted`, **no debit**)
5. Responder agent computes answer from the session's profile snapshot
6. Grounding verifier recomputes the rule; mismatch → `unavailable`, **no debit**
7. Egress validation: answer must be in the predicate's declared domain
8. Atomic debit, transcript append, sign, return

The single non-obvious rule: failures never debit. Charging for rejected or
unavailable queries would let a curious requester learn boundary shape from
cost signals.

## Failure semantics (all fail closed)

| Failure | Behavior on B |
|---|---|
| A unreachable / bad response signature | Existing no-summary path → T1 restricted |
| Unknown pseudonym (404 at open) | Same no-summary path → T1 |
| Budget exhausted mid-session | Decide on evidence in hand; safety floor still applies |
| Query rejected (off-grammar) | Treated as agent bug; decide conservatively |
| Answer unavailable | Facet treated as non-informative; never re-asked in-session |
| Idle timeout / max turns | Session closes; decide conservatively |

Invariant: no failure path ever increases disclosure or increases granted
access relative to the success path.

One deliberate asymmetry: **uncertainty restricts, it never rejects
outright**. An early-stopped negotiation (budget out, limits hit) decides
against the worst-case risk bound, but may only decide T0_REJECT when
established facts alone warrant it — otherwise the floor of the fallback
posture is T1 restricted, matching today's no-summary behavior. Rejection is
an evidence-based decision, not a default.

## Audit objects

Three records per decision:

1. **Budget ledger** (durable, Network A) — spent points per
   (pseudonym, requester, window); the disclosure metric.
2. **Transcript** (durable, Network A) — ordered Q/A pairs with per-turn
   signatures, grammar version, final tier; hash returned at close.
3. **Access decision log** (durable, Network B, existing) — extended with
   `transcript_hash` so both sides' records reconcile.

## Relationship to the existing one-shot path

`/v1/summary/request` remains untouched and runnable. Network B selects the
path with `NEGOTIATION_ENABLED`; when the flag is off — or when any step of
the negotiated path fails — behavior is exactly today's. The one-shot path
doubles as the evaluation baseline.
