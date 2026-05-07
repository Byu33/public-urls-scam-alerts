# AGENTS.md

## Cursor Cloud specific instructions

### Product overview

This is a Python data pipeline that aggregates consumer fraud data from two public government sources (BBB Scam Tracker and CFPB complaints), detects anomalies, and generates weekly intelligence briefings. All data is stored in a hosted Supabase (PostgreSQL) instance.

### Required secrets

- `SUPABASE_URL` — Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase service role key (preferred; `SUPABASE_KEY` or `SUPABASE_ANON_KEY` also accepted)

### Running the pipeline

```bash
python3 bbb/run_pipeline.py              # Full pipeline (BBB + CFPB)
python3 bbb/run_pipeline.py --bbb-only   # BBB pipeline only
python3 bbb/run_pipeline.py --skip-fetch # Skip BBB fetch, reuse existing data
python3 bbb/run_pipeline.py --start-step 3  # Start from step N (e.g. 3 = detect anomalies)
python3 database/purge_narratives.py     # Daily narrative purge
python3 database/purge_narratives.py --dry-run  # Purge dry-run (safe, no writes)
```

### Key caveats

- **No lint/test/build tooling is configured.** There is no `pytest`, `flake8`, `mypy`, or similar tool in the repo. Validation is done by running the pipeline scripts directly.
- **Step 1 (BBB fetch) is slow.** It scrapes `bbb.org` one page at a time with 1-second delays. A full week's data (~2700 records) takes ~7 minutes. Use `--skip-fetch` or `--start-step 2` to bypass when iterating on later steps.
- **All scripts must be run from within their directory or use `python3 bbb/...` from the repo root.** The `run_pipeline.py` script adjusts `sys.path` to find sibling modules.
- **`python3` not `python`.** The VM has `python3` on PATH; the bare `python` command is not available.
- **No `.env` files are committed.** Credentials come from environment variables injected by Cursor Cloud secrets. The code also checks `.env.local` and `.env` if present.
- **External network access is required** to reach `bbb.org` and `consumerfinance.gov` APIs. No API keys needed for those endpoints.
