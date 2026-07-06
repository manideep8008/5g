# Code walkthrough: understanding the negotiated attestation system

A staged reading path through the codebase. Each stage has: the files in
reading order, the core idea, a command that proves the stage works, and a
self-check — questions you should be able to answer before moving on. Total
time if done honestly: ~2 days. Do the stages in order; each builds on the
previous one.

The one-sentence mental model to keep throughout:

> Network B asks, Network A answers — but B can only ask questions from a
> priced menu (the grammar), A only answers what its evidence provably
> supports (the verifier), every answer costs budget (the ledger), and
> everything lands on a signed receipt (the transcript).

---

## Stage 0 — The big picture (30 minutes, no code)

Read, in order:

1. [../README.md](../README.md) — what the system is, the demo matrix.
2. [design/grammar.md](design/grammar.md) — the 8 questions, their prices,
   their grounding rules. **This table is the whole privacy claim.**
3. [design/protocol.md](design/protocol.md) — the session lifecycle and the
   normative gate order.

Self-check:
- Why does B drive the conversation but A control the boundary? What breaks
  if you swap that?
- Why are questions typed predicates instead of free text? (Three reasons —
  disclosure surface, prompt injection, pricing.)
- Why do rejected queries cost nothing? (Hint: what could B learn from
  being charged for a rejection?)

## Stage 1 — Network A's evidence base (the pre-existing pipeline)

Everything the agents will ever say is derived from this data. Reading
order:

1. [../laptop_a/network_a/collector/collector_main.py](../laptop_a/network_a/collector/collector_main.py)
   — tails the AMF log, scrapes the UPF. Note the "current IMSI" trick: OAI
   emits mid-procedure lines without an IMSI.
2. [../laptop_a/network_a/identity/identity_mapper.py](../laptop_a/network_a/identity/identity_mapper.py)
   — IMSI → HMAC pseudonym. The raw IMSI never leaves this module. Network B
   computes the *same* pseudonym independently
   ([../laptop_b/network_b/contract/identity.py](../laptop_b/network_b/contract/identity.py))
   — that's the identity contract between the networks.
3. [../laptop_a/network_a/db.py](../laptop_a/network_a/db.py) — one
   `StorageBackend` protocol, two implementations (in-memory for dev/tests,
   Postgres for deployment). Every new feature added a method to all three
   blocks — find `debit_budget` in each and compare how atomicity is
   achieved (a lock vs a conditional `UPDATE ... RETURNING`).
4. [../laptop_a/network_a/summary/summary_generator.py](../laptop_a/network_a/summary/summary_generator.py)
   — `build_profile()` flattens sessions into one aggregate; the
   `classify_*` functions bucket rates into enums using thresholds from
   [../laptop_a/config/network_a_config.yaml](../laptop_a/config/network_a_config.yaml);
   `generate_summary()` is the **old one-shot path** — still alive, it's
   the evaluation baseline.

Run: `cd laptop_a && python3 -m pytest tests/test_profile_builder.py tests/test_summary_generator.py -q`

Self-check:
- A UE has 8 auth failures in 40 attempts. What `auth_stability` does it
  get, and from which config line?
- Why does `build_profile` returning one flat aggregate make "recovering"
  and "still troubled" UEs indistinguishable? (This is the thesis
  motivation — be able to say it precisely.)

## Stage 2 — The grammar and the budget (the privacy machinery)

Reading order:

1. [../laptop_a/config/grammar.yaml](../laptop_a/config/grammar.yaml) — the
   menu. Every predicate: args, closed answer domain, cost, responder.
2. [../laptop_a/network_a/negotiation/grammar.py](../laptop_a/network_a/negotiation/grammar.py)
   — `validate_query` (can this be asked?) and `validate_answer` (may this
   leave?). Note `validate_answer` is the *egress* check — the last line of
   defense even if everything upstream is buggy.
3. [../laptop_a/network_a/negotiation/ledger.py](../laptop_a/network_a/negotiation/ledger.py)
   — windowed budget keyed `(pseudonym, requester, window)`. The window is
   why re-attaching a UE repeatedly can't harvest unlimited answers.

Run: `cd laptop_a && python3 -m pytest tests/test_grammar.py tests/test_ledger.py -q`

Read one test closely: `test_free_text_never_validates` in
[../laptop_a/tests/test_grammar.py](../laptop_a/tests/test_grammar.py) —
it *is* the non-leakage property, as a test.

Self-check:
- Why must debit-and-answer be atomic? What corrupts if they're not?
- Why is `resource_novelty` (cost 20) priced so that 5 probes drain the
  budget? What attack does that price defend against?
- Trace `test_concurrent_debits_never_overspend` — where exactly is the
  race prevented in each backend?

## Stage 3 — The responder agents and the verifier (Network A's brain)

Reading order:

1. [../laptop_a/network_a/summary/timeline.py](../laptop_a/network_a/summary/timeline.py)
   — the same sessions as `build_profile`, split into time buckets. This is
   what gives A a sense of *direction*.
2. [../laptop_a/network_a/summary/agents/evidence.py](../laptop_a/network_a/summary/agents/evidence.py)
   — the curated snapshot agents reason over. Taken **once per session** so
   every answer comes from consistent data.
3. [../laptop_a/network_a/summary/agents/grounding.py](../laptop_a/network_a/summary/agents/grounding.py)
   — **the most important file on the A side.** One pure function per
   predicate; the executable form of grammar.md. Note it *reuses* the
   `classify_*` functions from Stage 1 — the old bucketing code became the
   verification layer.
4. The three responders (`trend_agent.py`, `anomaly_agent.py`,
   `behavioral_agent.py`) — deliberately trivial in v1: they delegate to
   grounding. Their value is the *seam*: an LLM-backed variant replaces one
   `answer()` function and nothing else.
5. [../laptop_a/network_a/summary/agents/verifier.py](../laptop_a/network_a/summary/agents/verifier.py)
   + [orchestrator.py](../laptop_a/network_a/summary/agents/orchestrator.py)
   — generator/checker separation, timeouts, and the rule that every
   failure collapses to `unavailable`.

Run: `cd laptop_a && python3 -m pytest tests/test_grounding.py tests/test_orchestrator.py -q`

Read closely: `test_lying_responder_is_blocked_by_verifier` — a
monkeypatched agent claims "decreasing" when the truth is "flat" and the
verifier blocks it. This test is why you can put an LLM in an agent later
without weakening the privacy claim.

Self-check:
- Why is the verifier a *separate module* from the agents when v1 agents
  just call grounding anyway? (What changes when agents become LLMs?)
- `anomaly_status` says "resolved" for a flag nobody ever cleared. By what
  rule, and why must answering be a pure read (no DB writes)?
- What happens if a responder crashes mid-answer? Chase the exception
  through `orchestrator.answer_query`.

## Stage 4 — Boundary control and the session (the only door)

Reading order:

1. [../laptop_a/network_a/negotiation/schemas.py](../laptop_a/network_a/negotiation/schemas.py)
   — the wire contract. B has a byte-identical mirror.
2. [../laptop_a/network_a/negotiation/session.py](../laptop_a/network_a/negotiation/session.py)
   — in-memory session store, idle timeout (120 s), max turns (12). Note
   sessions are deliberately volatile; only ledger + transcripts are
   durable. Why is losing in-flight sessions on restart acceptable?
3. [../laptop_a/network_a/negotiation/boundary.py](../laptop_a/network_a/negotiation/boundary.py)
   — **read `handle_query` line by line against the gate order in
   protocol.md.** Session state → grammar → budget → responder → egress →
   atomic debit. Confirm each failure exit debits nothing and lands on the
   transcript.
4. [../laptop_a/network_a/api/routes.py](../laptop_a/network_a/api/routes.py)
   — the three `/v1/attestation/*` routes: thin HTTP translation, signing
   via the same `require_signed_request` / `signed_json_response` as the
   old endpoint. No new crypto anywhere.

Run: `cd laptop_a && python3 -m pytest tests/test_boundary.py tests/test_signed_attestation_api.py -q`

Hands-on: start A and drive a negotiation manually —

    cd laptop_a && uvicorn network_a.api.app:app --port 8001
    curl -X POST localhost:8001/v1/admin/seed-scenarios
    # then walk session→query→close with signed requests (see
    # tests/test_signed_attestation_api.py for how to sign)

Self-check:
- Why is the profile snapshotted at session open instead of per query?
- Why do *rejected* turns go on the transcript?
- Recompute a transcript hash by hand from a stored transcript
  (`test_transcript_hash_is_recomputable` shows how). Why does
  recomputability matter for audit?

## Stage 5 — Network B's decision agent (the deciding brain)

This is the intellectual core of the B side. Reading order:

1. [../laptop_b/network_b/policy/policy_engine.py](../laptop_b/network_b/policy/policy_engine.py)
   — the *old* risk model first: `FIELD_RISK_MAP`, `DEFAULT_WEIGHTS`,
   `compute_risk_score`, `risk_to_max_tier`, `apply_safety_floor`. The
   negotiated path reuses these exact semantics.
2. [../laptop_b/network_b/negotiation/belief.py](../laptop_b/network_b/negotiation/belief.py)
   — **risk as an interval.** Work one example by hand on paper:

   Minimal attestation says `anomalous` + `recent_anomaly`. Then:
   - behaviour term: 1.0 × 0.15 = **0.15** (known)
   - anomaly term: unknown status ∈ {resolved 0.05 … active 0.20}
   - auth, pdu, traffic: unknown ∈ [0, weight]
   - → risk ∈ [0.20, 1.00] → tiers T3…T0 → *must ask questions*.

   Now add `auth_stability=medium` (0.125, trend unknown → [0.0625, 0.125]),
   `pdu=high` (0), `traffic=volatile` with `trend=decreasing` (0.10),
   `anomaly_status=resolved` (0.05), `trend_auth=decreasing` (0.0625):
   risk = 0.3625 exactly → both bounds T2 → **decide T2**. That's the
   recovering UE's 90-point negotiation, and it's pinned in
   [../laptop_b/tests/test_decision_agent.py](../laptop_b/tests/test_decision_agent.py).

3. [../laptop_b/network_b/negotiation/decision_agent.py](../laptop_b/network_b/negotiation/decision_agent.py)
   — the loop: stop when tier is certain / pick highest value-per-cost
   question / conservative stops. Find the "uncertainty restricts, never
   rejects" rule and read the comment.
4. [../laptop_b/network_b/negotiation/session_client.py](../laptop_b/network_b/negotiation/session_client.py)
   — the signed client; every failure → None → caller falls back.
5. [../laptop_b/network_b/decision/decision_service.py](../laptop_b/network_b/decision/decision_service.py)
   — `negotiation_enabled()` flag, `negotiate_decision()`, and the fallback
   chain: negotiation → one-shot summary → no-summary T1.

Run: `cd laptop_b && python3 -m pytest tests/test_decision_agent.py -q`

Self-check:
- Why may the agent stop the moment `tier_for(risk_min) == tier_for(risk_max)`?
  What is provable at that moment?
- Why does an `unavailable` answer pin the facet at *worst case* forever?
  What would go wrong if unknowns stayed optimistic?
- The safety floor lifts the "anomalous label → T1" cap when
  `anomaly_status == resolved`. Justify that to a skeptical examiner.
  (Hint: the label aggregates the same window the status query
  disaggregates.)
- Why exactly one decision agent on B but a *team* on A? (Accountability
  vs decomposition-by-question-class.)

## Stage 6 — End-to-end and the evaluation (the proof)

1. [../tests_e2e/test_negotiated_e2e.py](../tests_e2e/test_negotiated_e2e.py)
   — both real stacks in one process via `httpx.ASGITransport`. Read the
   failure drills: dead A, tampered channel, mid-session tamper — every
   severed wire lands on T1.
2. [../evaluation/scenarios.py](../evaluation/scenarios.py) — six
   archetypes; **ground truth = the full-information decision** (all facets
   grounded by A's own rules, same risk semantics both paths use). Be able
   to defend this definition.
3. [../evaluation/runner.py](../evaluation/runner.py) — the replay and the
   fixed path's 90-point price (a documented lower bound — biased *against*
   the negotiated path, the safe direction).
4. Run it and read the output table:

       python3 -m evaluation.run

Self-check:
- Why is pricing the fixed summary at 90 points conservative for the
  thesis claim rather than generous?
- The 17% "over-grant" at budget ≤ 50 — what is it exactly, why is it
  deliberate, and why does it vanish at budget ≥ 75?
- Why does the frontier saturate at budget 100? What does that say about
  the grammar's cost calibration?

---

## The one exercise that ties it all together

Trace `UE_SIM_RECOVERING` from attach to T2, writing down every function in
call order. The chain, as a checklist:

1. B: [attachment_watcher.py](../laptop_b/network_b/collector/attachment_watcher.py)
   `watch_attachments` → `trigger_access_decision` (pseudonymises IMSI)
2. B: `POST /v1/access/request` → `handle_access_request`
   ([decision_service.py](../laptop_b/network_b/decision/decision_service.py))
   → flag on → `negotiate_decision` → `negotiate`
3. B→A: `SessionClient.open` — signed → A: `require_signed_request` →
   `boundary.open_session` → `gather_evidence` (profile snapshot!) →
   `generate_behavioural_summary` → minimal attestation, budget 100
4. B: `risk_bounds` → interval [0.20, 1.00], tiers differ →
   `candidate_questions` → `auth_stability` (0.25 width / 15 pts wins)
5. B→A: `SessionClient.query` → A gates in `boundary.handle_query`:
   signature → session `begin_turn` → `grammar.validate_query` →
   budget check → `orchestrator.answer_query` → `behavioral_agent.answer`
   → `grounding.ground` → `verifier.verify` → `grammar.validate_answer`
   → `ledger.debit` (atomic) → transcript append → signed answer "medium"
6. Repeat: pdu, traffic, trend(traffic), trend(auth), anomaly_status —
   watch the interval narrow to [0.3625, 0.3625]
7. B: tier stable → T2 → `apply_negotiated_floor` (resolved → no clip) →
   `SessionClient.close` → A seals transcript, returns hash
8. B: `AccessDecision` with `negotiated=True`, transcript hash,
   `ENFORCEMENT_MAP[T2]` (50 Mbps, 60 s monitoring) → `log_decision`

Every numbered step has a test. If you can narrate this chain from memory
with the *why* at each gate, you understand the system.

## Likely examiner questions → where the answer lives

| Question | Answer lives in |
|---|---|
| "How do you *prove* raw data can't leak?" | One door (`boundary.py`), egress check (`grammar.validate_answer`), `test_free_text_never_validates` |
| "The LLM could hallucinate an answer" | `verifier.py` + the lying-responder test; v1 agents are deterministic anyway |
| "Couldn't B reconstruct the profile by asking repeatedly?" | Ledger windows (`ledger.py`), grammar closure, `test_budget_persists_across_sessions_in_same_window` |
| "What if Network A is down / compromised in transit?" | Failure drills in `tests_e2e`; every path → T1, `negotiated=False` |
| "Why is the LLM safe in the decision loop?" | It isn't in the loop yet — and the ceiling is deterministic: `risk_bounds` + the ceiling property test (50 random seeds) |
| "Where's the privacy–utility tradeoff quantified?" | `evaluation/` — frontier.png; fixed 89.1%@90pts vs negotiated 97.8%@54pts |
| "What's your trust assumption?" | grammar.md threat rationale: honest-but-curious B; A's honesty assumed (grounding is A checking itself) |
