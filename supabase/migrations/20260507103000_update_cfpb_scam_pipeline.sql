-- Extend CFPB tables for the scam-focused 16-category pipeline.

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
