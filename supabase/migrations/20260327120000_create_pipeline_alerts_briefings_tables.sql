create table if not exists public.pipeline_runs (
    id bigserial primary key,
    status text not null,
    started_at timestamptz not null default now(),
    completed_at timestamptz,
    steps_completed integer not null default 0,
    total_steps integer not null default 8,
    error_details text,
    created_at timestamptz not null default now()
);

create index if not exists idx_pipeline_runs_status_started_at
    on public.pipeline_runs (status, started_at desc);

create table if not exists public.anomaly_alerts (
    id bigserial primary key,
    run_id bigint references public.pipeline_runs(id) on delete set null,
    week_ending date not null,
    scam_type text not null,
    state text,
    short_deviation numeric,
    long_deviation numeric,
    current_count integer,
    alert_tier text,
    scope text,
    detection_level text,
    dollar_trajectory boolean default false,
    narrative_batches jsonb,
    batch_count integer,
    total_narratives_sampled integer,
    sample_size_requested integer,
    created_at timestamptz not null default now()
);

create index if not exists idx_anomaly_alerts_week_tier
    on public.anomaly_alerts (week_ending, alert_tier);

create index if not exists idx_anomaly_alerts_scam_state
    on public.anomaly_alerts (scam_type, state);

create table if not exists public.weekly_briefings (
    id bigserial primary key,
    run_id bigint references public.pipeline_runs(id) on delete set null,
    week_ending date not null,
    briefing_status text not null default 'pending',
    briefing_markdown text not null,
    top_finding_summary text,
    national_summary text,
    total_reports_this_week integer,
    total_reports_last_week integer,
    week_over_week_change numeric,
    top_5_states jsonb,
    top_5_scam_types jsonb,
    new_scam_types jsonb,
    national_flags jsonb,
    created_at timestamptz not null default now()
);

create index if not exists idx_weekly_briefings_week_status
    on public.weekly_briefings (week_ending, briefing_status);
