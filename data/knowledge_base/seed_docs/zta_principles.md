# Zero Trust Architecture Principles for 5G Access Tiering

These principles guide tier decisions for UEs whose behavioural summaries
arrive from Network A. They are deliberately conservative: a UE earns
trust through observable behaviour, never through prior assumption.

## Never trust by default

Every access request is treated as if it originated from an untrusted
network. A UE that has previously been granted full access does not
retain that privilege across sessions when its behaviour profile
changes. Past tier assignments are evidence, not entitlement.

## Verify with current evidence

Tier decisions must be grounded in the most recent behavioural summary,
not in historical bias. Authentication stability, PDU session stability,
and traffic pattern are observable proxies. A summary older than the
configured window must trigger re-collection rather than reuse.

## Anomaly invalidates elevated trust

A `recent_anomaly` flag of `true` is sufficient cause to deny `T3` even
if all other indicators are stable. Anomalous behaviour signals either
a compromised device, an unauthorised use, or an emerging fault — none
of which warrants unconstrained access. The recommended ceiling for
any UE flagged anomalous in the current window is `T2_MONITORED_ACCESS`.

## Authentication degradation tightens the ceiling

When `auth_stability` is `low`, the UE has produced repeated failed or
unstable authentication attempts. This warrants `T1_RESTRICTED_ACCESS`
or stricter, regardless of other indicators. Authentication is the
foundation of identity; an unstable foundation cannot support a higher
tier.

## Conservative fallback on missing evidence

When Network A is unreachable, when the behavioural summary is missing
fields, or when retrieval evidence is judged inadequate, the system
must default to `T1_RESTRICTED_ACCESS`. It is safer to under-grant and
re-evaluate than to over-grant and apologise.

## LLM proposals are advisory, not authoritative

The hybrid policy engine treats the LLM's tier proposal as a hypothesis
that must clear the deterministic safety floor. The LLM may tighten a
decision (propose a lower tier than rules require) but must never loosen
it. Any LLM output proposing a tier above the safety-floor ceiling is
clipped without further negotiation.

## Evidence must be auditable

Every tier decision should preserve the snippets that informed it —
policy clauses, ZTA principles, and historical precedents — so that
operators can later reconstruct why a UE received the tier it did. An
unexplainable allow is worse than a justifiable deny.
