alter table if exists public.bbb_scam_reports
	add column if not exists scam_subtype text,
	add column if not exists narrative_expires_at timestamp;

create table if not exists public.bbb_trends (
	id serial primary key,
	week_ending date,
	scam_type text,
	state text,
	report_count integer,
	avg_dollar_amount numeric,
	created_at timestamp default now()
);

do $$
begin
	if exists (
		select 1
		from pg_class
		where oid = 'public.bbb_trends'::regclass
	) and not exists (
		select 1
		from pg_constraint
		where conname = 'uq_bbb_trends_week_ending_scam_type_state'
			and conrelid = 'public.bbb_trends'::regclass
	) then
		alter table public.bbb_trends
			add constraint uq_bbb_trends_week_ending_scam_type_state
			unique (week_ending, scam_type, state);
	end if;
end $$;

create index if not exists idx_bbb_trends_week_ending_scam_type
	on public.bbb_trends (week_ending, scam_type);
