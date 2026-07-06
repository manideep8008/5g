# Negotiated attestation — two-laptop distribution

Zero-trust cross-network access control between two 5G core networks:
**Network A** (the sensing domain, `laptop_a/`) holds a UE's behavioural
history; **Network B** (the deciding domain, `laptop_b/`) decides an access
tier when that UE attaches. Instead of a fixed six-field summary, B's
decision agent *negotiates*: it asks A's responder agents targeted questions
from a closed grammar, each answer grounded in evidence and charged against
a privacy budget, until the tier is certain.

Design documents (read these first):

- [docs/design/grammar.md](docs/design/grammar.md) — the question grammar
  and cost table: the entire disclosure surface
- [docs/design/protocol.md](docs/design/protocol.md) — session protocol,
  state machine, failure semantics

## Layout

    laptop_a/   Network A: collectors, evidence base, responder agents,
                grammar + budget + boundary control, attestation API (:8001)
    laptop_b/   Network B: attachment watcher, decision agent, policy
                engine + RAG, access decision API (:8002)
    tests_e2e/  Cross-network end-to-end suite (both packages, one process)

## Tests

    cd laptop_a && python3 -m pytest          # Network A suite
    cd laptop_b && python3 -m pytest          # Network B suite
    python3 -m pytest tests_e2e               # end-to-end, from the dist root

## Running the negotiated demo

On both machines, set a shared secret (byte-identical) and keep signing on:

    export HMAC_SECRET_KEY=<random hex 64>
    export REQUIRE_SIGNED_REQUESTS=true

Laptop A — start the attestation API and seed the demo UEs:

    cd laptop_a
    uvicorn network_a.api.app:app --host 0.0.0.0 --port 8001
    curl -X POST http://localhost:8001/v1/admin/seed-scenarios

Laptop B — point at A, enable negotiation, start the decision API:

    cd laptop_b
    export NETWORK_A_URL=http://<laptop-a-ip>:8001
    export NEGOTIATION_ENABLED=true
    uvicorn network_b.api.app:app --host 0.0.0.0 --port 8002

Trigger decisions (or let the attachment watcher fire them on real
REGISTRATION_COMPLETE events):

    curl -X POST http://localhost:8002/v1/access/request \
      -H 'content-type: application/json' \
      -d '{"request_id":"demo-1","ue_pseudonym":"UE_SIM_RECOVERING",
           "requested_slice":"eMBB","requested_dnn":"internet",
           "requested_service":"standard_data",
           "timestamp":"2026-07-06T12:00:00Z"}'

Expected demo matrix (also pinned by `tests_e2e/`):

| UE | Tier | Budget spent | Why |
|---|---|---|---|
| UE_SIM_NORMAL | T3 | 0 | attested normal — fast path, zero questions |
| UE_SIM_RECOVERING | **T2** | 90 | trend/anomaly queries reveal the trouble is historical |
| UE_SIM_SUSPICIOUS | T1 | 90 | same questions, opposite answers — trouble is live |
| UE_SIM_ANOMALOUS | T0 | 65 | evidence-confirmed reject |

With `NEGOTIATION_ENABLED=false` (the default) Network B uses the original
one-shot summary path — which is also the evaluation baseline. Every failure
of the negotiated path (A down, bad signatures, drained budget) fails closed
to at most T1 restricted access.
