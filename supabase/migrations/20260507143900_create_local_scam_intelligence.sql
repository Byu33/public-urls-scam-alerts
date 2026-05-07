CREATE TABLE IF NOT EXISTS local_crime_reports (
    id                   SERIAL PRIMARY KEY,
    source               TEXT NOT NULL,
    city                 TEXT NOT NULL,
    report_date          DATE,
    offense_type         TEXT,
    offense_category     TEXT,
    description          TEXT,
    location_description TEXT,
    community_area       TEXT,
    borough              TEXT,
    division             TEXT,
    latitude             NUMERIC,
    longitude            NUMERIC,
    is_scam_confirmed    BOOLEAN DEFAULT TRUE,
    scam_category        TEXT,
    ingested_at          TIMESTAMP DEFAULT NOW(),
    UNIQUE (source, report_date, latitude, longitude)
);

CREATE INDEX IF NOT EXISTS idx_local_crime_city_date
    ON local_crime_reports(city, report_date);

CREATE INDEX IF NOT EXISTS idx_local_crime_scam_type
    ON local_crime_reports(scam_category, report_date);

CREATE TABLE IF NOT EXISTS local_news_mentions (
    id                   SERIAL PRIMARY KEY,
    source               TEXT NOT NULL,
    city                 TEXT NOT NULL,
    published_at         TIMESTAMP,
    headline             TEXT,
    summary              TEXT,
    url                  TEXT UNIQUE,
    scam_keywords_found  TEXT,
    keyword_match_count  INTEGER DEFAULT 0,
    sentiment            TEXT,
    scam_category        TEXT,
    is_scam_specific     BOOLEAN DEFAULT TRUE,
    ingested_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_local_news_city_date
    ON local_news_mentions(city, published_at);

CREATE INDEX IF NOT EXISTS idx_local_news_scam_category
    ON local_news_mentions(scam_category, published_at);

ALTER TABLE local_crime_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE local_news_mentions ENABLE ROW LEVEL SECURITY;
