-- SentinelTrap schema.
-- Runs once, on an empty data directory, via docker-entrypoint-initdb.d.
-- `events` is the only high-volume table and the only hypertable.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- events

CREATE TABLE events (
    event_id    TEXT        NOT NULL,          -- ULID, generated at the decoy; dedupe key
    ts          TIMESTAMPTZ NOT NULL,
    decoy       TEXT        NOT NULL,
    protocol    TEXT        NOT NULL,
    src_ip      INET        NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    action      TEXT        NOT NULL,
    payload     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    raw         TEXT,                           -- original decoy log line, never discarded
    session_id  UUID,                           -- set by the sessioniser, not at ingest
    PRIMARY KEY (event_id, ts)
);

SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day');

ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'decoy',
    timescaledb.compress_orderby   = 'ts DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days');

CREATE INDEX ON events (src_ip, ts DESC);
CREATE INDEX ON events USING GIN (payload);
CREATE INDEX ON events (session_id) WHERE session_id IS NOT NULL;

-- Continuous aggregates back the dashboard's timeline charts with no rollup job.
CREATE MATERIALIZED VIEW events_1min
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 minute', ts) AS bucket,
       decoy,
       count(*)                    AS event_count,
       count(DISTINCT src_ip)      AS unique_ips
FROM events
GROUP BY bucket, decoy
WITH NO DATA;

CREATE MATERIALIZED VIEW events_1hour
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', ts) AS bucket,
       decoy,
       count(*)                   AS event_count,
       count(DISTINCT src_ip)     AS unique_ips
FROM events
GROUP BY bucket, decoy
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_1min',
    start_offset => INTERVAL '3 hours',
    end_offset   => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute');

SELECT add_continuous_aggregate_policy('events_1hour',
    start_offset => INTERVAL '3 days',
    end_offset   => INTERVAL '1 hour',
    schedule_interval => INTERVAL '10 minutes');

-- -------------------------------------------------------------- sessions

-- One row per (src_ip, decoy) group with no more than a 15-minute gap.
-- This is the unit everything downstream reasons about.
CREATE TABLE sessions (
    session_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    src_ip       INET        NOT NULL,
    decoy        TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    ended_at     TIMESTAMPTZ,
    event_count  INTEGER     NOT NULL DEFAULT 0,
    features     JSONB,                          -- the ~25-feature vector
    closed       BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX ON sessions (src_ip, started_at DESC);
CREATE INDEX ON sessions (closed, started_at) WHERE NOT closed;

-- ------------------------------------------------------------ ip_profiles

CREATE TABLE ip_profiles (
    ip               INET PRIMARY KEY,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    country          TEXT,
    asn              INTEGER,
    org              TEXT,
    is_tor           BOOLEAN NOT NULL DEFAULT FALSE,
    is_vpn           BOOLEAN NOT NULL DEFAULT FALSE,
    total_sessions   INTEGER NOT NULL DEFAULT 0,
    max_threat_score NUMERIC(5,2) NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------- alerts

CREATE TYPE alert_status AS ENUM ('new', 'triaged', 'confirmed', 'false_positive');

CREATE TABLE alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    threat_score    NUMERIC(5,2) NOT NULL,
    predicted_class TEXT,
    confidence      REAL,
    anomaly_score   REAL,
    triggered_rules TEXT[] NOT NULL DEFAULT '{}',
    reason          TEXT,                        -- human-readable, always populated
    status          alert_status NOT NULL DEFAULT 'new'
);

-- The triage queue.
CREATE INDEX ON alerts (status, threat_score DESC);
CREATE INDEX ON alerts (session_id);

-- ------------------------------------------------------------- campaigns

CREATE TABLE campaigns (
    campaign_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_label INTEGER NOT NULL,
    member_count  INTEGER NOT NULL,
    signature     TEXT,                          -- shared command chain or path pattern
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL
);

CREATE TABLE campaign_members (
    campaign_id UUID NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    session_id  UUID NOT NULL REFERENCES sessions(session_id)  ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, session_id)
);

-- ------------------------------------------------------------- artifacts

-- Dropped binaries and payload bodies. Stored on disk by hash, never in the DB,
-- and never executed.
CREATE TABLE artifacts (
    sha256      TEXT PRIMARY KEY,
    session_id  UUID REFERENCES sessions(session_id) ON DELETE SET NULL,
    filename    TEXT,
    size        BIGINT,
    mime        TEXT,
    stored_path TEXT NOT NULL,
    vt_verdict  TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------- rules

CREATE TABLE rules (
    rule_id   TEXT PRIMARY KEY,                  -- from the YAML filename
    name      TEXT NOT NULL,
    severity  REAL NOT NULL CHECK (severity BETWEEN 0 AND 1),
    pattern   TEXT NOT NULL,
    enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    hit_count BIGINT  NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------- labels

-- source = 'rule' or 'human'. Keeping them apart is what makes evaluation
-- honest: train on whatever you like, but report metrics ONLY on human labels.
CREATE TYPE label_source AS ENUM ('rule', 'human');

CREATE TABLE labels (
    session_id  UUID NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    source      label_source NOT NULL,
    labelled_by TEXT,
    labelled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, source)
);

CREATE INDEX ON labels (source, label);

-- -------------------------------------------------------- model_versions

CREATE TABLE model_versions (
    version    TEXT PRIMARY KEY,
    algo       TEXT NOT NULL,
    trained_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    n_samples  INTEGER,
    precision  REAL,
    recall     REAL,
    f1         REAL,
    metrics    JSONB,                            -- per-class breakdown
    active     BOOLEAN NOT NULL DEFAULT FALSE
);

-- Only one active model at a time.
CREATE UNIQUE INDEX ON model_versions (active) WHERE active;

-- ----------------------------------------------------------------- users

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                 -- bcrypt
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
