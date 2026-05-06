CREATE TABLE IF NOT EXISTS ue_identity (
    pseudonym       VARCHAR(32) PRIMARY KEY,
    imsi_hmac       VARCHAR(64) NOT NULL UNIQUE,
    first_seen      TIMESTAMPTZ NOT NULL,
    network_b_id    VARCHAR(64) NOT NULL,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS ue_session (
    session_id           BIGSERIAL PRIMARY KEY,
    pseudonym            VARCHAR(32) REFERENCES ue_identity(pseudonym),
    started_at           TIMESTAMPTZ NOT NULL,
    ended_at             TIMESTAMPTZ,
    duration_sec         INTEGER,
    registration_success BOOLEAN NOT NULL,
    auth_attempts        INTEGER NOT NULL DEFAULT 0,
    auth_failures        INTEGER NOT NULL DEFAULT 0,
    pdu_attempts         INTEGER NOT NULL DEFAULT 0,
    pdu_failures         INTEGER NOT NULL DEFAULT 0,
    requested_slice      VARCHAR(16),
    requested_dnn        VARCHAR(64),
    bytes_uplink         BIGINT NOT NULL DEFAULT 0,
    bytes_downlink       BIGINT NOT NULL DEFAULT 0,
    peak_throughput_kbps INTEGER,
    spike_count          INTEGER NOT NULL DEFAULT 0,
    cell_id              VARCHAR(16),
    raw_log_pointer      VARCHAR(256)
);

CREATE INDEX IF NOT EXISTS ix_ue_session_pseudonym_time
    ON ue_session(pseudonym, started_at DESC);

CREATE TABLE IF NOT EXISTS ue_risk_flag (
    flag_id        BIGSERIAL PRIMARY KEY,
    pseudonym      VARCHAR(32) REFERENCES ue_identity(pseudonym),
    flagged_at     TIMESTAMPTZ NOT NULL,
    flag_type      VARCHAR(32),
    severity       VARCHAR(16),
    evidence       JSONB,
    cleared_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS summary_disclosure (
    disclosure_id    BIGSERIAL PRIMARY KEY,
    request_id       VARCHAR(64) NOT NULL,
    pseudonym        VARCHAR(32) NOT NULL,
    network_b_id     VARCHAR(64) NOT NULL,
    disclosed_at     TIMESTAMPTZ NOT NULL,
    summary_payload  JSONB NOT NULL,
    requested_fields TEXT[]
);
