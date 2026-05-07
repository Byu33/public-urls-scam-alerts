# Weekly Scam Intelligence Briefing

Generated: 2026-05-07T08:29:38.029950+00:00

## Phase Status
- Builder: PASS
- Verifier: READY
- Data Quality: HOLD
- Output: PASS

## Data Summary
- BBB records ingested: 16818
- CFPB records ingested: 24
- Local crime records: 1
- BBB anomalies: {'CRITICAL': 0, 'ALERT': 0, 'WATCH': 0}
- CFPB anomalies: {'CRITICAL': 0, 'ALERT': 0, 'WATCH': 0}
- Cross source signals: 0

## Warnings and Follow-up
- bbb/fetch_reports.py exceeded 30s; continuing with existing Supabase bbb_scam_reports data for downstream trend generation.
- No live local crime source exists in this repository; generated configured placeholder output.
- Supabase MCP server requires authentication, so table counts were queried through the repo Supabase client.
- Invalid state codes in bbb_scam_reports: AB, BC
