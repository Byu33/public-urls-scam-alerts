-- CFPB Pipeline Tables
-- Three tables: cfpb_trends, cfpb_complaints, cfpb_anomaly_alerts

-- ── cfpb_trends ───────────────────────────────────────────────────────────────
-- Weekly aggregate counts from the CFPB trends API per product/issue/state combo.
-- state = 'NATIONAL' for national-level rows.

CREATE TABLE IF NOT EXISTS cfpb_trends (
    id           SERIAL PRIMARY KEY,
    week_ending  DATE        NOT NULL,
    product      TEXT        NOT NULL,
    sub_product  TEXT,
    issue        TEXT        NOT NULL,
    state        TEXT        NOT NULL,
    report_count INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMP   NOT NULL DEFAULT NOW(),
    UNIQUE (week_ending, product, issue, state)
);

CREATE INDEX IF NOT EXISTS idx_cfpb_trends_week
    ON cfpb_trends (week_ending, product, issue);

CREATE INDEX IF NOT EXISTS idx_cfpb_trends_state
    ON cfpb_trends (state, week_ending);

-- ── cfpb_complaints ───────────────────────────────────────────────────────────
-- Individual CFPB complaint records sampled for flagged anomaly clusters.
-- Narratives expire after 7 days; purged by daily purge job.

CREATE TABLE IF NOT EXISTS cfpb_complaints (
    id                   TEXT        PRIMARY KEY,
    date_received        DATE,
    product              TEXT,
    sub_product          TEXT,
    issue                TEXT,
    company_name         TEXT,
    state                TEXT,
    zip_code             TEXT,
    narrative            TEXT,
    narrative_expires_at TIMESTAMP,
    narrative_purged_at  TIMESTAMP,
    ingested_at          TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cfpb_complaints_product_date
    ON cfpb_complaints (product, issue, date_received);

CREATE INDEX IF NOT EXISTS idx_cfpb_complaints_state
    ON cfpb_complaints (state, date_received);

-- ── cfpb_anomaly_alerts ───────────────────────────────────────────────────────
-- Flagged CFPB anomalies per pipeline run. Includes brand analysis fields
-- populated by the Copilot Chat agent after narratives are sampled.

CREATE TABLE IF NOT EXISTS cfpb_anomaly_alerts (
    id                    SERIAL      PRIMARY KEY,
    run_timestamp         TIMESTAMP,
    product               TEXT,
    issue                 TEXT,
    state                 TEXT,
    alert_tier            TEXT,
    scope                 TEXT,
    short_deviation       NUMERIC,
    long_deviation        NUMERIC,
    current_count         INTEGER,
    week_ending           DATE,
    detection_level       TEXT,
    top_company           TEXT,
    narrative_batch       JSONB,
    analysis_status       TEXT        NOT NULL DEFAULT 'pending_analysis',
    brands_mentioned      TEXT,
    dominant_brand        TEXT,
    impersonated_entity   TEXT,
    attack_vector         TEXT,
    payment_method        TEXT,
    pattern_summary       TEXT,
    analysis_completed_at TIMESTAMP,
    created_at            TIMESTAMP   NOT NULL DEFAULT NOW()
);
