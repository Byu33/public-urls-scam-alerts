-- ============================================================
-- CFPB MIGRATIONS — paste this entire file into
-- Supabase SQL Editor and click Run
-- ============================================================

-- ── Migration 1: Create CFPB tables ──────────────────────────

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

-- ── Migration 2: Extend weekly_briefings ─────────────────────

ALTER TABLE weekly_briefings
    ADD COLUMN IF NOT EXISTS cfpb_critical_count INTEGER,
    ADD COLUMN IF NOT EXISTS cfpb_alert_count    INTEGER,
    ADD COLUMN IF NOT EXISTS cfpb_watch_count    INTEGER,
    ADD COLUMN IF NOT EXISTS top_cfpb_companies  TEXT,
    ADD COLUMN IF NOT EXISTS cfpb_top_finding    TEXT;
