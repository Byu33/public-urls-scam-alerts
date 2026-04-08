create table if not exists public.bbb_scam_reports (
	id text primary key,
	reported_date date,
	scam_type text,
	scam_subtype text,
	state text,
	zip text,
	dollar_amount numeric,
	contact_method text,
	business_name text,
	narrative text,
	narrative_expires_at timestamp,
	narrative_purged_at timestamp,
	ingested_at timestamp default now()
);

create index if not exists idx_bbb_scam_reports_scam_type_reported_date
	on public.bbb_scam_reports (scam_type, reported_date);

create index if not exists idx_bbb_scam_reports_state_reported_date
	on public.bbb_scam_reports (state, reported_date);

create table if not exists public.bbb_trends (
	id serial primary key,
	week_ending date,
	scam_type text,
	state text,
	report_count integer,
	avg_dollar_amount numeric,
	created_at timestamp default now(),
	constraint uq_bbb_trends_week_ending_scam_type_state
		unique (week_ending, scam_type, state)
);

create index if not exists idx_bbb_trends_week_ending_scam_type
	on public.bbb_trends (week_ending, scam_type);
