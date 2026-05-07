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

-- ── Migration 3: Scam-focused CFPB pipeline columns ───────────

ALTER TABLE cfpb_trends
    ADD COLUMN IF NOT EXISTS scam_type TEXT,
    ADD COLUMN IF NOT EXISTS priority TEXT;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'cfpb_trends'
          AND constraint_name = 'cfpb_trends_week_ending_product_issue_state_key'
    ) THEN
        ALTER TABLE cfpb_trends
            DROP CONSTRAINT cfpb_trends_week_ending_product_issue_state_key;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'cfpb_trends'
          AND constraint_name = 'cfpb_trends_week_product_issue_scam_state_key'
    ) THEN
        ALTER TABLE cfpb_trends
            ADD CONSTRAINT cfpb_trends_week_product_issue_scam_state_key
            UNIQUE (week_ending, product, issue, scam_type, state);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_cfpb_trends_scam_week
    ON cfpb_trends (scam_type, state, week_ending);

ALTER TABLE cfpb_complaints
    ADD COLUMN IF NOT EXISTS sub_issue TEXT;

CREATE INDEX IF NOT EXISTS idx_cfpb_complaints_sub_issue
    ON cfpb_complaints (sub_issue, date_received);

ALTER TABLE cfpb_anomaly_alerts
    ADD COLUMN IF NOT EXISTS scam_type TEXT,
    ADD COLUMN IF NOT EXISTS sub_issue TEXT,
    ADD COLUMN IF NOT EXISTS top_sub_issue TEXT,
    ADD COLUMN IF NOT EXISTS priority TEXT,
    ADD COLUMN IF NOT EXISTS detection_window_short INTEGER DEFAULT 8,
    ADD COLUMN IF NOT EXISTS detection_window_long INTEGER DEFAULT 16;

UPDATE cfpb_anomaly_alerts
SET state = 'NATIONAL'
WHERE state IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'cfpb_anomaly_alerts'
          AND constraint_name = 'cfpb_alerts_week_scam_state_level_key'
    ) THEN
        ALTER TABLE cfpb_anomaly_alerts
            ADD CONSTRAINT cfpb_alerts_week_scam_state_level_key
            UNIQUE (week_ending, scam_type, state, detection_level);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_cfpb_alerts_scam_week
    ON cfpb_anomaly_alerts (scam_type, week_ending, alert_tier);
