# Tier Rationale Reference

Plain-language description of when each access tier is appropriate. The
LLM should use this to align its proposals with operator intent. The
deterministic safety floor still applies on top of any LLM proposal.

## T3 — Full access

Granted when all behavioural indicators are stable and there is no
recent anomaly. Typical profile:
- `auth_stability=high`
- `pdu_session_stability=high`
- `traffic_pattern=stable`
- `recent_anomaly=false`
- `behaviour_label=normal`

The UE is treated as a trusted endpoint with full slice and service
access. A single elevated indicator should drop the proposal to `T2`.

## T2 — Monitored access

Granted when one or two indicators warrant caution but no hard rule
triggers. Active monitoring is enabled and bandwidth is capped at the
mid-tier limit. This is the appropriate tier when:
- `recent_anomaly=true` but no other indicator is elevated, or
- `behaviour_label=suspicious` with stable authentication, or
- `traffic_pattern=volatile` with otherwise normal behaviour.

The intent is to allow useful service while collecting more evidence
before promoting the UE to `T3` or demoting it to `T1`.

## T1 — Restricted access

Granted when multiple indicators are elevated, when authentication is
unstable, or when the UE has been labelled anomalous. Typical triggers:
- `auth_stability=low` (always clipped to T1 or stricter)
- `behaviour_label=anomalous` (always clipped to T1 or stricter)
- Two or more medium-risk indicators present simultaneously.

Bandwidth is heavily capped and only `standard_data` is permitted.

## T0 — Reject

Granted only when the deterministic risk score exceeds 0.80, indicating
overwhelming evidence of compromise or misuse. No service is granted.
The decision must include an explicit reason citing which indicators
combined to produce the rejection so the operator can review.
