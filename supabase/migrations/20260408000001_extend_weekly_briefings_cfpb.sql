-- Extend weekly_briefings with CFPB summary columns.
-- These are populated by generate_weekly_briefing.py after CFPB anomaly detection.

ALTER TABLE weekly_briefings
    ADD COLUMN IF NOT EXISTS cfpb_critical_count INTEGER,
    ADD COLUMN IF NOT EXISTS cfpb_alert_count    INTEGER,
    ADD COLUMN IF NOT EXISTS cfpb_watch_count    INTEGER,
    ADD COLUMN IF NOT EXISTS top_cfpb_companies  TEXT,
    ADD COLUMN IF NOT EXISTS cfpb_top_finding    TEXT;
