from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from supabase import Client, create_client


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
OUTPUT_DIR = REPO_ROOT / "sharepoint_output"
LOG_PATH = AGENTS_DIR / "orchestrator.log"

MAX_RETRIES = 3
SUPABASE_TABLES = [
    "bbb_scam_reports",
    "bbb_trends",
    "anomaly_alerts",
    "weekly_briefings",
    "pipeline_runs",
    "cfpb_trends",
    "cfpb_complaints",
    "cfpb_anomaly_alerts",
]
CRITICAL_TABLES = {"bbb_scam_reports", "bbb_trends", "cfpb_trends"}
VALID_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DC", "DE", "FL",
    "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME",
    "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH",
    "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI",
    "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "NATIONAL",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def append_log(message: str) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(f"{utc_now()} {message}\n")


def initialize() -> None:
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text(
        f"START {utc_now()}\nretry_count=0\nmax_retries={MAX_RETRIES}\n",
        encoding="utf-8",
    )


def load_module(script_path: str, module_name: str) -> Any:
    path = REPO_ROOT / script_path
    if not path.exists():
        raise FileNotFoundError(f"Missing required script: {script_path}")
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scrub_result(value: Any) -> Any:
    if isinstance(value, dict):
        scrubbed: dict[str, Any] = {}
        for key, item in value.items():
            if key == "records" and isinstance(item, list):
                scrubbed["records_count"] = len(item)
                scrubbed["records_sample"] = scrub_result(item[:3])
            elif key in {"narrative", "briefing_markdown"} and isinstance(item, str):
                scrubbed[key] = item[:500]
            else:
                scrubbed[key] = scrub_result(item)
        return scrubbed
    if isinstance(value, list):
        if len(value) > 50:
            return {
                "count": len(value),
                "sample": scrub_result(value[:10]),
            }
        return [scrub_result(item) for item in value]
    return value


def run_step(script_path: str, action: Callable[[], Any]) -> dict[str, Any]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    started_at = time.time()
    result: Any = None
    status = "PASS"
    error = ""

    append_log(f"STEP START {script_path}")
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            result = action()
        except Exception:
            status = "FAIL"
            error = traceback.format_exc()
            print(error, file=sys.stderr)
    append_log(f"STEP COMPLETE {script_path} status={status}")

    return {
        "script": script_path,
        "status": status,
        "elapsed_seconds": round(time.time() - started_at, 2),
        "output": stdout.getvalue(),
        "errors": stderr.getvalue() + error,
        "result": scrub_result(result),
    }


def load_env() -> None:
    load_dotenv(REPO_ROOT / ".env.local")
    load_dotenv(REPO_ROOT / ".env")
    load_dotenv()


def get_supabase_client() -> Client:
    load_env()
    url = os.getenv("SUPABASE_URL")
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )
    if not url or not key:
        raise ValueError(
            "Missing Supabase credentials. Set SUPABASE_URL and one of "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY, or SUPABASE_ANON_KEY."
        )
    return create_client(url, key)


def run_builder_phase() -> dict[str, Any]:
    cfpb_trend_data: list[dict[str, Any]] = []

    bbb_fetch = load_module("bbb/fetch_reports.py", "orchestrator_bbb_fetch_reports")
    cfpb_fetch = load_module("cfpb/fetch_trends.py", "orchestrator_cfpb_fetch_trends")
    local_fetch = load_module("local/fetch_local_crime.py", "orchestrator_local_fetch")
    bbb_build = load_module("bbb/build_trends.py", "orchestrator_bbb_build_trends")
    cfpb_build = load_module("cfpb/build_cfpb_trends.py", "orchestrator_cfpb_build_trends")

    def fetch_cfpb_wrapper() -> dict[str, Any]:
        nonlocal cfpb_trend_data
        cfpb_fetch.REQUEST_DELAY_SECONDS = float(os.getenv("ORCHESTRATOR_CFPB_DELAY_SECONDS", "0.1"))
        cfpb_fetch.REQUEST_TIMEOUT_SECONDS = int(os.getenv("ORCHESTRATOR_CFPB_TIMEOUT_SECONDS", "10"))
        cfpb_fetch.MAX_RETRIES = int(os.getenv("ORCHESTRATOR_CFPB_MAX_RETRIES", "1"))
        cfpb_fetch.RETRY_WAIT_SECONDS = int(os.getenv("ORCHESTRATOR_CFPB_RETRY_WAIT_SECONDS", "1"))
        lookback_weeks = int(os.getenv("ORCHESTRATOR_CFPB_LOOKBACK_WEEKS", "2"))
        raw_states = os.getenv("ORCHESTRATOR_CFPB_STATES", "CA")
        states = None if raw_states.strip().upper() == "ALL" else [
            state.strip().upper() for state in raw_states.split(",") if state.strip()
        ]
        cfpb_trend_data = cfpb_fetch.fetch_cfpb_trends(
            lookback_weeks=lookback_weeks,
            states=states,
        )
        return {
            "trend_rows": len(cfpb_trend_data),
            "sample_rows": cfpb_trend_data[:3],
            "lookback_weeks": lookback_weeks,
            "states": states if states is not None else "ALL",
        }

    def build_cfpb_wrapper() -> dict[str, Any]:
        if cfpb_trend_data:
            return cfpb_build.build_cfpb_trends(cfpb_trend_data)
        return cfpb_build.main()

    steps = [
        run_step("bbb/fetch_reports.py", bbb_fetch.run_fetch_pipeline),
        run_step("cfpb/fetch_trends.py", fetch_cfpb_wrapper),
        run_step("local/fetch_local_crime.py", local_fetch.fetch_local_crime),
        run_step("bbb/build_trends.py", bbb_build.run_build_trends),
        run_step("cfpb/build_cfpb_trends.py", build_cfpb_wrapper),
    ]
    issues = [
        f"{step['script']} failed: {step['errors'][:1000]}"
        for step in steps
        if step["status"] != "PASS"
    ]
    warnings: list[str] = []
    for step in steps:
        result = step.get("result")
        if isinstance(result, dict):
            warnings.extend(str(w) for w in result.get("warnings", []) or [])

    bbb_fetch_result = steps[0].get("result") if steps else {}
    cfpb_fetch_result = steps[1].get("result") if len(steps) > 1 else {}
    local_result = steps[2].get("result") if len(steps) > 2 else {}

    report = {
        "phase": "builder",
        "generated_at": utc_now(),
        "overall_status": "FAIL" if issues else "PASS",
        "steps": steps,
        "issues": issues,
        "warnings": warnings,
        "data_summary": {
            "bbb_records_ingested": int(
                (bbb_fetch_result or {}).get("total_records_upserted")
                or (bbb_fetch_result or {}).get("total_records_parsed")
                or 0
            ),
            "cfpb_records_ingested": int((cfpb_fetch_result or {}).get("trend_rows") or 0),
            "local_crime_records": int((local_result or {}).get("records") or 0),
        },
    }
    write_json(AGENTS_DIR / "builder_report.json", report)
    append_log("BUILDER COMPLETE")
    return report


def _tier_counts(anomalies: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(row.get("alert_tier", "WATCH")).upper() for row in anomalies)
    return {tier: int(counts.get(tier, 0)) for tier in ("CRITICAL", "ALERT", "WATCH")}


def run_bbb_detection() -> dict[str, Any]:
    module = load_module("bbb/detect_anomalies.py", "orchestrator_bbb_detect_anomalies")
    client = module.get_supabase_client()
    df = module.pull_trends_data(client)
    if df.empty:
        print("No trend data found for the last 16 weeks.")
        anomalies: list[dict[str, Any]] = []
    else:
        national = module.detect_anomalies_national(df, trace=False)
        state = module.detect_anomalies(df, trace=False)
        anomalies = module.merge_detection_results(national, state)
        module.print_results(anomalies)
    return {
        "anomalies": anomalies,
        "anomalies_detected": len(anomalies),
        "tier_counts": _tier_counts(anomalies),
    }


def run_cfpb_detection() -> dict[str, Any]:
    module = load_module("cfpb/detect_cfpb_anomalies.py", "orchestrator_cfpb_detect_anomalies")
    client = module.get_supabase_client()
    df = module.pull_cfpb_trends(client)
    if df.empty:
        print("No CFPB trend data found for the last 24 weeks.")
        anomalies: list[dict[str, Any]] = []
    else:
        national = module.detect_cfpb_anomalies_national(df, trace=False)
        state = module.detect_cfpb_anomalies(df, trace=False)
        anomalies = module.merge_cfpb_results(national, state)
        module.print_cfpb_results(anomalies)
    return {
        "anomalies": anomalies,
        "anomalies_detected": len(anomalies),
        "tier_counts": _tier_counts(anomalies),
    }


def query_table_counts(client: Client) -> tuple[dict[str, int | None], list[str]]:
    counts: dict[str, int | None] = {}
    issues: list[str] = []
    for table in SUPABASE_TABLES:
        try:
            response = client.table(table).select("*", count="exact").limit(0).execute()
            counts[table] = int(response.count or 0)
        except Exception as exc:
            counts[table] = None
            if table in CRITICAL_TABLES:
                issues.append(f"Critical Supabase table unavailable: {table}: {exc}")
            else:
                issues.append(f"Supabase table count unavailable: {table}: {exc}")
    return counts, issues


def run_verifier_phase() -> dict[str, Any]:
    bbb_step = run_step("bbb/detect_anomalies.py", run_bbb_detection)
    cfpb_step = run_step("cfpb/detect_cfpb_anomalies.py", run_cfpb_detection)
    issues = [
        f"{step['script']} failed: {step['errors'][:1000]}"
        for step in (bbb_step, cfpb_step)
        if step["status"] != "PASS"
    ]
    warnings = [
        "Supabase MCP server requires authentication, so table counts were queried through the repo Supabase client."
    ]

    table_counts: dict[str, int | None] = {}
    try:
        client = get_supabase_client()
        table_counts, table_issues = query_table_counts(client)
        for issue in table_issues:
            if "Critical" in issue:
                issues.append(issue)
            else:
                warnings.append(issue)
    except Exception as exc:
        issues.append(f"Supabase row count query failed: {exc}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sharepoint_files = sorted(str(path.relative_to(REPO_ROOT)) for path in OUTPUT_DIR.iterdir() if path.is_file())
    bbb_counts = ((bbb_step.get("result") or {}).get("tier_counts") or {})
    cfpb_counts = ((cfpb_step.get("result") or {}).get("tier_counts") or {})
    report = {
        "phase": "verifier",
        "generated_at": utc_now(),
        "overall_status": "NOT READY" if issues else "READY",
        "steps": [bbb_step, cfpb_step],
        "table_counts": table_counts,
        "sharepoint_output_files": sharepoint_files,
        "anomaly_summary": {
            "bbb_anomalies_by_tier": bbb_counts,
            "cfpb_anomalies_by_tier": cfpb_counts,
            "bbb_anomalies_total": int(sum(int(v or 0) for v in bbb_counts.values())),
            "cfpb_anomalies_total": int(sum(int(v or 0) for v in cfpb_counts.values())),
        },
        "issues": issues,
        "warnings": warnings,
    }
    write_json(AGENTS_DIR / "verifier_report.json", report)
    append_log("VERIFIER COMPLETE")
    return report


def fetch_rows(client: Client, table: str, columns: str, limit: int = 1000) -> list[dict[str, Any]]:
    response = client.table(table).select(columns).limit(limit).execute()
    return response.data or []


def extract_verifier_anomalies(verifier: dict[str, Any], index: int) -> list[dict[str, Any]]:
    try:
        rows = verifier["steps"][index]["result"]["anomalies"]
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def build_cross_source_signals(
    bbb_anomalies: list[dict[str, Any]],
    cfpb_anomalies: list[dict[str, Any]],
) -> dict[str, Any]:
    bbb_types = {str(row.get("scam_type", "")).lower() for row in bbb_anomalies if row.get("scam_type")}
    cfpb_text = {
        f"{row.get('product', '')} {row.get('issue', '')}".lower()
        for row in cfpb_anomalies
    }
    overlap_map = {
        "identity theft": ["identity theft", "getting a credit card"],
        "phishing": ["fraud or scam"],
        "investment": ["fraud or scam"],
        "online purchase": ["purchase", "transfer"],
        "romance": ["fraud or scam"],
        "government agency imposter": ["fraud or scam", "false statements"],
    }
    signals: list[dict[str, Any]] = []
    for bbb_type, keywords in overlap_map.items():
        if bbb_type not in bbb_types:
            continue
        match_count = sum(1 for text in cfpb_text if any(keyword in text for keyword in keywords))
        if match_count:
            signals.append(
                {
                    "signal_type": "bbb_cfpb_overlap",
                    "description": f"{bbb_type.title()} appears in both BBB and CFPB anomaly signals.",
                    "count": match_count,
                }
            )
    return {"count": len(signals), "signals": signals}


def run_quality_phase() -> dict[str, Any]:
    verifier = read_json(AGENTS_DIR / "verifier_report.json")
    bbb_anomalies = extract_verifier_anomalies(verifier, 0)
    cfpb_anomalies = extract_verifier_anomalies(verifier, 1)
    issues: list[str] = []
    warnings: list[str] = []
    narrative_samples: list[dict[str, Any]] = []
    invalid_states: dict[str, list[str]] = {"bbb_scam_reports": [], "cfpb_trends": []}

    try:
        client = get_supabase_client()
        narrative_samples = fetch_rows(
            client,
            "bbb_scam_reports",
            "id,reported_date,scam_type,state,narrative",
            limit=5,
        )
        for row in narrative_samples:
            if isinstance(row.get("narrative"), str):
                row["narrative"] = row["narrative"][:500]
        if not narrative_samples:
            warnings.append("No BBB narrative samples returned from bbb_scam_reports.")

        bbb_state_rows = fetch_rows(client, "bbb_scam_reports", "state", limit=5000)
        cfpb_state_rows = fetch_rows(client, "cfpb_trends", "state", limit=5000)
        invalid_states["bbb_scam_reports"] = sorted(
            {
                str(row.get("state", "")).strip().upper()
                for row in bbb_state_rows
                if row.get("state") and str(row.get("state", "")).strip().upper() not in VALID_STATES
            }
        )
        invalid_states["cfpb_trends"] = sorted(
            {
                str(row.get("state", "")).strip().upper()
                for row in cfpb_state_rows
                if row.get("state") and str(row.get("state", "")).strip().upper() not in VALID_STATES
            }
        )
        for table, states in invalid_states.items():
            if states:
                issues.append(f"Invalid state codes in {table}: {', '.join(states)}")
    except Exception as exc:
        issues.append(f"Data quality Supabase queries failed: {exc}")

    deviations: list[float] = []
    for row in bbb_anomalies + cfpb_anomalies:
        for key in ("short_deviation", "long_deviation"):
            try:
                deviations.append(float(row.get(key)))
            except (TypeError, ValueError):
                continue
    deviation_range = {
        "min": min(deviations) if deviations else None,
        "max": max(deviations) if deviations else None,
        "count": len(deviations),
    }
    if deviations and any(abs(value) > 20 for value in deviations):
        issues.append("Deviation score outside expected range +/-20.")

    tier_distribution = {
        "bbb": _tier_counts(bbb_anomalies),
        "cfpb": _tier_counts(cfpb_anomalies),
    }
    cross_source_signals = build_cross_source_signals(bbb_anomalies, cfpb_anomalies)

    report = {
        "phase": "quality",
        "generated_at": utc_now(),
        "overall_status": "HOLD" if issues else "READY",
        "narrative_samples": scrub_result(narrative_samples),
        "deviation_score_ranges": deviation_range,
        "alert_tier_distribution": tier_distribution,
        "state_code_validity": {
            "invalid_states": invalid_states,
            "valid": not any(invalid_states.values()),
        },
        "cross_source_signals": cross_source_signals,
        "issues": issues,
        "warnings": warnings,
    }
    write_json(AGENTS_DIR / "quality_report.json", report)
    append_log("QUALITY COMPLETE")
    return report


def run_output_phase() -> dict[str, Any]:
    output_module = load_module("output/write_to_excel.py", "orchestrator_write_to_excel")
    output_step = run_step("output/write_to_excel.py", output_module.write_outputs)
    required_files = [
        "Weekly_Briefing.md",
        "Scam_Intelligence_Briefing.xlsx",
        "BBB_Anomalies.csv",
        "CFPB_Anomalies.csv",
        "Cross_Source_Signals.csv",
        "Pipeline_Phase_Status.csv",
        "Supabase_Table_Counts.csv",
        "Local_Crime_LA.csv",
    ]
    existing = {path.name for path in OUTPUT_DIR.iterdir() if path.is_file()}
    missing = [name for name in required_files if name not in existing]
    issues = []
    if output_step["status"] != "PASS":
        issues.append(f"output/write_to_excel.py failed: {output_step['errors'][:1000]}")
    if missing:
        issues.append(f"Missing sharepoint_output files: {', '.join(missing)}")
    files = sorted(str(path.relative_to(REPO_ROOT)) for path in OUTPUT_DIR.iterdir() if path.is_file())
    report = {
        "phase": "output",
        "generated_at": utc_now(),
        "overall_status": "FAIL" if issues else "PASS",
        "steps": [output_step],
        "required_files": required_files,
        "files": files,
        "issues": issues,
        "warnings": [],
    }
    write_json(AGENTS_DIR / "output_report.json", report)
    append_log("OUTPUT COMPLETE")
    return report


def run_inline_fixer(target: str, issues: list[str]) -> None:
    append_log(f"FIXER START target={target}")
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for directory in ("local", "output"):
        (REPO_ROOT / directory).mkdir(parents=True, exist_ok=True)
    for issue in issues:
        append_log(f"FIXER ISSUE target={target} {issue[:500]}")
    missing_modules = [issue for issue in issues if "ModuleNotFoundError" in issue or "No module named" in issue]
    if missing_modules:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(REPO_ROOT / "requirements.txt")],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        append_log(f"FIXER ACTION target={target} reinstalled requirements")
    append_log(f"FIXER COMPLETE target={target}")


def phase_with_retries(name: str, runner: Callable[[], dict[str, Any]], ready_status: str, retry_count: int) -> tuple[dict[str, Any], int, bool]:
    while True:
        report = runner()
        if report.get("overall_status") == ready_status:
            return report, retry_count, True
        if retry_count < MAX_RETRIES:
            retry_count += 1
            append_log(f"{name} FAILED attempt {retry_count}")
            run_inline_fixer(name.lower(), report.get("issues", []))
            continue
        append_log(f"{name} FAILED max retries reached")
        print(f"HUMAN ESCALATION REQUIRED: {name} failed after {MAX_RETRIES} retries.")
        for issue in report.get("issues", []):
            print(f"- {issue}")
        return report, retry_count, False


def priority_files(files: list[str]) -> list[str]:
    preferred = [
        "sharepoint_output/Weekly_Briefing.md",
        "sharepoint_output/Scam_Intelligence_Briefing.xlsx",
        "sharepoint_output/BBB_Anomalies.csv",
        "sharepoint_output/CFPB_Anomalies.csv",
        "sharepoint_output/Cross_Source_Signals.csv",
        "sharepoint_output/Supabase_Table_Counts.csv",
        "sharepoint_output/Pipeline_Phase_Status.csv",
        "sharepoint_output/Local_Crime_LA.csv",
    ]
    ordered = [name for name in preferred if name in files]
    ordered.extend(name for name in sorted(files) if name not in ordered)
    return ordered


def format_duration(seconds: float) -> str:
    total = int(round(seconds))
    minutes, secs = divmod(total, 60)
    return f"{minutes} minutes {secs} seconds"


def final_report(started_at: float) -> str:
    builder = read_json(AGENTS_DIR / "builder_report.json")
    verifier = read_json(AGENTS_DIR / "verifier_report.json")
    quality = read_json(AGENTS_DIR / "quality_report.json")
    output = read_json(AGENTS_DIR / "output_report.json")
    elapsed = time.time() - started_at

    builder_status = "PASS" if builder.get("overall_status") == "PASS" else "FAIL"
    verifier_status = "PASS" if verifier.get("overall_status") == "READY" else "FAIL"
    quality_status = quality.get("overall_status", "HOLD")
    output_status = "PASS" if output.get("overall_status") == "PASS" else "FAIL"

    data_summary = builder.get("data_summary", {})
    anomaly_summary = verifier.get("anomaly_summary", {})
    cross_count = quality.get("cross_source_signals", {}).get("count", 0)
    files = priority_files(output.get("files", []))

    attention: list[str] = []
    for report in (builder, verifier, quality, output):
        attention.extend(report.get("issues", []) or [])
    if quality_status == "HOLD" and not quality.get("issues"):
        attention.append("Data quality is HOLD.")
    status = "BRIEFING READY" if not attention and builder_status == "PASS" and verifier_status == "PASS" and output_status == "PASS" else "NEEDS ATTENTION"

    border = "\u2550" * 42
    lines = [
        border,
        "SCAM INTELLIGENCE PIPELINE - FINAL REPORT",
        datetime.now(timezone.utc).isoformat(),
        border,
        "",
        "PHASE RESULTS:",
        f"  Builder:     {builder_status}",
        f"  Verifier:    {verifier_status}",
        f"  Data Quality: {quality_status}",
        f"  Output:      {output_status}",
        "",
        "DATA SUMMARY:",
        f"  BBB records ingested:    {data_summary.get('bbb_records_ingested', 0)}",
        f"  CFPB records ingested:   {data_summary.get('cfpb_records_ingested', 0)}",
        f"  Local crime records:     {data_summary.get('local_crime_records', 0)}",
        f"  BBB anomalies detected:  {anomaly_summary.get('bbb_anomalies_by_tier', {})}",
        f"  CFPB anomalies detected: {anomaly_summary.get('cfpb_anomalies_by_tier', {})}",
        f"  Cross source signals:    {cross_count}",
        "",
        "FILES READY FOR COPILOT CHAT UPLOAD:",
    ]
    lines.extend(f"  {name}" for name in files)
    lines.extend(
        [
            "",
            f"TOTAL PIPELINE TIME: {format_duration(elapsed)}",
            "",
            f"STATUS: {status}",
            border,
        ]
    )
    if status == "NEEDS ATTENTION":
        lines.append("NEEDS ATTENTION:")
        lines.extend(f"- {item}" for item in attention)

    text = "\n".join(lines)
    append_log("FINAL SUMMARY")
    append_log(text)
    return text


def main() -> int:
    started_at = time.time()
    initialize()
    retry_count = 0

    builder, retry_count, ok = phase_with_retries("BUILDER", run_builder_phase, "PASS", retry_count)
    if not ok:
        return 1

    verifier, retry_count, ok = phase_with_retries("VERIFIER", run_verifier_phase, "READY", retry_count)
    if not ok:
        return 1

    quality = run_quality_phase()
    if quality.get("overall_status") == "HOLD":
        append_log("QUALITY HOLD rerun once")
        run_inline_fixer("quality", quality.get("issues", []))
        quality = run_quality_phase()
        if quality.get("overall_status") == "HOLD":
            append_log("QUALITY HOLD continuing with warnings noted")

    run_output_phase()
    print(final_report(started_at))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
