# Question grammar and cost table

Version 1 — the disclosure surface of the negotiated attestation protocol.

This document defines every question Network B may ask Network A about a UE,
the exact set of answers each question can produce, what each answer costs
against the privacy budget, and the deterministic rule that grounds each
answer in Network A's raw evidence. Anything not in this table is rejected
at the protocol boundary. Together with the budget, this table *is* the
privacy claim: the grammar bounds what **kind** of information can leave
Network A, the budget bounds **how much**.

## Design rules

Every predicate row must satisfy three properties:

1. **Closed output domain.** Answers are drawn from a small fixed enum —
   never free text, never numbers. An answer from a domain of *k* outcomes
   reveals at most log2(k) bits about the UE profile, which is what makes
   the budget interpretable as a disclosure bound.
2. **Deterministic grounding rule.** Each answer must be recomputable from
   the `UeProfile` / timeline by a pure function. Responder agents may reason
   however they like internally; the grounding verifier recomputes the rule
   and blocks any answer it does not entail.
3. **Cost proportional to disclosure.** Cost scales with the size of the
   output domain and with how many raw signals the answer correlates.
   Questions that would narrow the raw feature space too far are not
   priced high — they are absent from the table.

Reserved statuses `unavailable` (insufficient data or responder timeout) and
`rejected` (off-grammar query) are protocol-level statuses, not answers.
Neither is ever debited.

## Budget

| Parameter | Value | Rationale |
|---|---|---|
| Total | 100 points | Allows roughly 4–7 questions per decision |
| Scope | (ue_pseudonym, requester_id, window) | Per-UE so one hard case cannot drain others; per-requester for multi-requester isolation |
| Window | 3600 s | Re-attaching the same UE repeatedly cannot harvest more than 100 points/hour |

A debit is atomic with its answer. If cost exceeds the remaining budget the
query is refused whole — there are no partial answers.

## Predicate table

| # | Predicate | Args | Answers | Cost | Responder |
|---|---|---|---|---|---|
| 1 | `trend(facet)` | facet ∈ {auth_failures, pdu_failures, traffic_spikes} | increasing / flat / decreasing | 10 | trend |
| 2 | `flag_age` | — | none / recent / old | 10 | anomaly |
| 3 | `auth_stability` | — | high / medium / low | 15 | behavioral |
| 4 | `pdu_stability` | — | high / medium / low | 15 | behavioral |
| 5 | `traffic_pattern` | — | stable / moderate / volatile | 15 | behavioral |
| 6 | `session_regularity` | — | regular / irregular | 15 | behavioral |
| 7 | `resource_novelty(kind, value)` | kind ∈ {slice, dnn}; value: identifier | known / novel | 20 | behavioral |
| 8 | `anomaly_status` | — | none / resolved / active | 25 | anomaly |

`identifier` means a string matching `^[A-Za-z0-9_-]{1,32}$` — the requested
slice or DNN name Network B already knows from its own attach context.

## Grounding rules

All rules operate on the window used by `build_profile()` (default 86400 s).
"H1" is the older half of the window's sessions ordered by `started_at`,
"H2" the recent half.

1. **trend(facet)** — `delta = rate(H2) − rate(H1)` where rate is
   auth failure rate, PDU failure rate, or spikes per session for the three
   facets respectively. `|delta| ≤ 0.05` → flat; `delta > 0.05` → increasing;
   otherwise decreasing. Either half empty of attempts → unavailable.
   *Cost 10: three outcomes over one already-bucketed facet.*
2. **flag_age** — no risk flags in the window → none; most recent
   `flagged_at` younger than 6 h → recent; otherwise old.
   *Cost 10: flag metadata only, no signal values.*
3. **auth_stability** — `classify_auth_stability(profile.auth_failure_rate)`
   with the thresholds in `network_a_config.yaml`. *Cost 15: re-disclosure
   of one bucketed facet of today's fixed summary.*
4. **pdu_stability** — `classify_pdu_stability(profile.pdu_failure_rate)`.
   *Cost 15: as above.*
5. **traffic_pattern** — `classify_traffic_pattern(profile.spike_rate)`.
   *Cost 15: as above.*
6. **session_regularity** — coefficient of variation of inter-session gaps
   (`started_at` deltas) over the window. Fewer than 3 sessions →
   unavailable; CV ≤ 0.5 → regular; otherwise irregular.
   *Cost 15: two outcomes but correlates timing metadata.*
7. **resource_novelty(kind, value)** — `value ∈ profile.known_slices`
   (or `known_dnns`) → known, else novel. *Cost 20: a membership oracle over
   a private inventory. Priced so that enumerating the inventory drains the
   budget after 5 probes; contrast with today's summary, which ships the
   whole slice list for free.*
8. **anomaly_status** — no risk flags in the window → none; flags exist but
   all are cleared, or the recent half H2 is clean (zero auth failures, zero
   PDU failures, zero spikes) → resolved; otherwise → active. The recency
   clause matters because collectors raise flags automatically but nothing
   clears them — a flag's condition can pass while the flag row stays open.
   Answering is a pure read: the rule never mutates flag state.
   *Cost 25: the most decision-moving answer in the table; correlates flag
   lifecycle with recent signal recurrence.*

## Versioning

`grammar.yaml` carries an integer `version`. Existing rows are immutable —
changing a domain, cost, or grounding rule requires a new predicate name and
a version bump. Additions bump the version. Network B learns the version at
session open; the transcript records it, so every audit is interpretable
against the grammar that was in force.

## Threat rationale

The adversary is an honest-but-curious Network B that follows the protocol
but adaptively chooses queries to reconstruct raw features. The grammar
keeps the question surface finite and enumerable; closed domains cap
bits-per-answer; the budget caps cumulative bits per window; rejected and
unavailable queries are never debited, so probing the boundary yields
neither information nor budget signal. Defending against a Network A that
lies in its answers is out of scope — A's honesty about its own evidence is
an assumption inherited from the existing one-shot design (grounding
verification is A checking itself, not B checking A).
