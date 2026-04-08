from __future__ import annotations

import sys
import traceback
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os

from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

import fetch_reports
import build_trends
import detect_anomalies
import sample_narratives
import generate_weekly_briefing

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from database import purge_narratives

TOTAL_STEPS = 8
UPSERT_BATCH_SIZE = 500


def load_env() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()


def get_supabase_client() -> Client:
    load_env()
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )
    if not supabase_url or not supabase_key:
        raise ValueError(
            "Missing SUPABASE credentials. Set SUPABASE_URL and one of "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY, or SUPABASE_ANON_KEY."
        )
    return create_client(supabase_url, supabase_key)


def print_step_header(name: str) -> None:
    print("\n" + "=" * 78)
    print(f"{name}")
    print("=" * 78)


def step_fetch() -> dict[str, Any]:
    result = fetch_reports.run_fetch_pipeline()
    print(
        f"STEP 1 result: fetched={result['total_records_parsed']} "
        f"saved={result['total_records_upserted']}"
    )
    return result


def step_build_trends() -> dict[str, Any]:
    result = build_trends.run_build_trends()
    print(
        f"STEP 2 result: source_rows={result.get('source_rows', 0)} "
        f"trend_rows={result.get('trend_rows', 0)} "
        f"upserted_rows={result.get('upserted_rows', 0)}"
    )
    return result


def step_detect_anomalies() -> dict[str, Any]:
    client = detect_anomalies.get_supabase_client()
    df = detect_anomalies.pull_trends_data(client)
    national = detect_anomalies.detect_anomalies_national(df, trace=False)
    state = detect_anomalies.detect_anomalies(df, trace=False)
    anomalies = detect_anomalies.merge_detection_results(national, state)

    tier_counts = Counter(a.get("alert_tier", "WATCH") for a in anomalies)
    print(
        "STEP 3 result: "
        f"total={len(anomalies)} | "
        f"CRITICAL={tier_counts.get('CRITICAL', 0)} "
        f"ALERT={tier_counts.get('ALERT', 0)} "
        f"WATCH={tier_counts.get('WATCH', 0)}"
    )

    return {
        "anomalies": anomalies,
        "tier_counts": {
            "CRITICAL": tier_counts.get("CRITICAL", 0),
            "ALERT": tier_counts.get("ALERT", 0),
            "WATCH": tier_counts.get("WATCH", 0),
        },
    }


def step_sample_narratives(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    if not anomalies:
        print("STEP 4 result: no anomalies detected this week, skipping narrative sampling.")
        return {"anomalies_with_narratives": []}

    tier_order = {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}
    sorted_anomalies = sorted(
        anomalies,
        key=lambda a: (
            tier_order.get(str(a.get("alert_tier", "WATCH")), 99),
            -float(a.get("short_deviation", 0.0) or 0.0),
        ),
    )

    anomalies_with_narratives: list[dict[str, Any]] = []

    for anomaly in sorted_anomalies:
        # Skip national-level anomalies (state=None); they don't have specific state narratives
        if anomaly.get("state") is None:
            print(
                f"SKIPPED (national-level): {anomaly.get('scam_type')} | "
                f"tier={anomaly.get('alert_tier')} (no state narratives for national anomalies)"
            )
            continue
        
        sampled = sample_narratives.sample_narratives_for_anomaly(anomaly)
        if sampled is None:
            print(
                "WARNING: no narratives sampled for "
                f"{anomaly.get('scam_type')} / {anomaly.get('state')} / {anomaly.get('alert_tier')}"
            )
            continue

        print(
            "Sampled narratives ready for Copilot Studio: "
            f"{anomaly.get('scam_type')} / {anomaly.get('state')} | "
            f"tier={anomaly.get('alert_tier')} | batches={sampled['batch_count']}"
        )
        anomalies_with_narratives.append(sampled)

    print(
        "STEP 4 result: "
        f"anomalies_with_narratives={len(anomalies_with_narratives)}"
    )
    return {"anomalies_with_narratives": anomalies_with_narratives}


def step_write_anomaly_alerts(
    client: Client,
    run_id: int | None,
    anomalies: list[dict[str, Any]],
    sampled_result: dict[str, Any],
) -> dict[str, Any]:
    if not anomalies:
        print("STEP 5 result: no anomalies to write.")
        return {"rows_inserted": 0}

    sampled_lookup: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    for item in sampled_result.get("anomalies_with_narratives", []):
        anomaly = item.get("anomaly", {})
        key = (
            anomaly.get("scam_type"),
            anomaly.get("state"),
            anomaly.get("alert_tier"),
            anomaly.get("week_ending"),
        )
        sampled_lookup[key] = item

    rows: list[dict[str, Any]] = []
    for anomaly in anomalies:
        key = (
            anomaly.get("scam_type"),
            anomaly.get("state"),
            anomaly.get("alert_tier"),
            anomaly.get("week_ending"),
        )
        sampled = sampled_lookup.get(key, {})

        rows.append(
            {
                "run_id": run_id,
                "week_ending": anomaly.get("week_ending"),
                "scam_type": anomaly.get("scam_type"),
                "state": anomaly.get("state"),
                "short_deviation": anomaly.get("short_deviation"),
                "long_deviation": anomaly.get("long_deviation"),
                "current_count": anomaly.get("current_count"),
                "alert_tier": anomaly.get("alert_tier"),
                "scope": anomaly.get("scope"),
                "detection_level": anomaly.get("detection_level"),
                "dollar_trajectory": bool(anomaly.get("dollar_trajectory", False)),
                "narrative_batches": sampled.get("batches"),
                "batch_count": sampled.get("batch_count"),
                "total_narratives_sampled": sampled.get("total_narratives_sampled"),
                "sample_size_requested": sampled.get("sample_size_requested"),
            }
        )

    inserted = 0
    for start in range(0, len(rows), UPSERT_BATCH_SIZE):
        batch = rows[start : start + UPSERT_BATCH_SIZE]
        client.table("anomaly_alerts").insert(batch).execute()
        inserted += len(batch)

    print(f"STEP 5 result: anomaly_alerts rows inserted={inserted}")
    return {"rows_inserted": inserted}


def step_generate_weekly_briefing(run_id: int | None) -> dict[str, Any]:
    result = generate_weekly_briefing.generate_weekly_briefing()

    if run_id is not None:
        client = get_supabase_client()
        client.table("weekly_briefings").update({"run_id": run_id}).eq(
            "week_ending", result.get("week_ending")
        ).is_("run_id", "null").execute()

    print(
        f"STEP 6 result: week_ending={result.get('week_ending')} "
        f"alerts_included={result.get('alerts_included', 0)}"
    )
    return result


def step_purge_narratives() -> dict[str, Any]:
    exit_code = purge_narratives.run_purge(dry_run=False)
    if exit_code != 0:
        print("WARNING: purge failed in write mode; retrying as dry-run for diagnostics.")
        dry_run_exit_code = purge_narratives.run_purge(dry_run=True)
        return {"exit_code": exit_code, "dry_run_exit_code": dry_run_exit_code}
    print("STEP 7 result: narrative purge completed successfully")
    return {"exit_code": exit_code}


def _is_missing_table_error(exc: Exception) -> bool:
    code = getattr(exc, "code", None)
    message = str(exc)
    return code == "PGRST205" or "Could not find the table" in message


def table_exists(client: Client, table_name: str) -> bool:
    try:
        client.table(table_name).select("*").limit(1).execute()
        return True
    except APIError as exc:
        if _is_missing_table_error(exc):
            return False
        raise


def create_pipeline_run(client: Client) -> int:
    payload = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "steps_completed": 0,
        "total_steps": TOTAL_STEPS,
    }
    response = client.table("pipeline_runs").insert(payload).execute()
    rows = response.data or []
    if not rows:
        raise RuntimeError("Failed to create pipeline_runs record")
    run_id = int(rows[0]["id"])
    print(f"pipeline_run_id: {run_id}")
    return run_id


def update_pipeline_run(client: Client, run_id: int, updates: dict[str, Any]) -> None:
    client.table("pipeline_runs").update(updates).eq("id", run_id).execute()


def print_final_report(
    started_at: float,
    step_timings: dict[str, float],
    detect_result: dict[str, Any],
    sampled_result: dict[str, Any],
    failures: list[str],
) -> None:
    runtime = time.time() - started_at
    tier_counts = detect_result.get("tier_counts", {"CRITICAL": 0, "ALERT": 0, "WATCH": 0})
    sampled = sampled_result.get("anomalies_with_narratives", [])

    print("\n" + "#" * 78)
    print("FINAL PIPELINE REPORT")
    print("#" * 78)
    print(f"pipeline_run_timestamp: {datetime.utcnow().isoformat()}Z")
    print(f"total_runtime_seconds: {runtime:.2f}")
    print("step_timing_breakdown_seconds:")
    for step_name, seconds in step_timings.items():
        print(f"- {step_name}: {seconds:.2f}")

    print("total_anomalies_detected_by_tier:")
    print(f"- CRITICAL: {tier_counts.get('CRITICAL', 0)}")
    print(f"- ALERT: {tier_counts.get('ALERT', 0)}")
    print(f"- WATCH: {tier_counts.get('WATCH', 0)}")
    print(f"total_anomalies_with_narratives_sampled: {len(sampled)}")

    print("anomalies_with_narratives_ready_for_copilot_studio:")
    if not sampled:
        print("- (none)")
    else:
        for item in sampled:
            anomaly = item.get("anomaly", {})
            batches = item.get("batches", [])
            print("-" * 78)
            print(f"scam_type: {anomaly.get('scam_type')}")
            print(f"state: {anomaly.get('state')}")
            print(f"alert_tier: {anomaly.get('alert_tier')}")
            print(f"scope: {anomaly.get('scope')}")
            print(f"short_deviation: {anomaly.get('short_deviation')}")
            print(f"long_deviation: {anomaly.get('long_deviation')}")
            print(f"current_count: {anomaly.get('current_count')}")
            print(f"week_ending: {anomaly.get('week_ending')}")
            print(f"batch_count: {item.get('batch_count')}")
            print(f"total_narratives_sampled: {item.get('total_narratives_sampled')}")
            for b_idx, batch in enumerate(batches, start=1):
                print(f"batch_{b_idx}_narratives_count: {len(batch)}")
                for n_idx, narrative in enumerate(batch, start=1):
                    print(f"  [{n_idx}] {narrative}")

    if failures:
        print("\nfailed_steps:")
        for failure in failures:
            print(f"- {failure}")
    else:
        print("\nfailed_steps: none")


def run_pipeline() -> None:
    started_at = time.time()
    failures: list[str] = []
    step_timings: dict[str, float] = {}

    load_env()

    pipeline_client: Client | None = None
    run_id: int | None = None
    steps_completed = 0
    has_pipeline_runs = False
    has_anomaly_alerts = False
    has_weekly_briefings = False

    try:
        pipeline_client = get_supabase_client()
        has_pipeline_runs = table_exists(pipeline_client, "pipeline_runs")
        has_anomaly_alerts = table_exists(pipeline_client, "anomaly_alerts")
        has_weekly_briefings = table_exists(pipeline_client, "weekly_briefings")

        if has_pipeline_runs:
            run_id = create_pipeline_run(pipeline_client)
        else:
            print("WARNING: pipeline_runs table is missing; run tracking disabled.")

        if not has_anomaly_alerts:
            print("WARNING: anomaly_alerts table is missing; alert persistence disabled.")
        if not has_weekly_briefings:
            print("WARNING: weekly_briefings table is missing; briefing persistence disabled.")
    except Exception as exc:
        failures.append(f"SUPABASE_CONNECT: {exc}")
        print("WARNING: Supabase pipeline client init failed. Some steps may fail.")

    detect_result: dict[str, Any] = {
        "anomalies": [],
        "tier_counts": {"CRITICAL": 0, "ALERT": 0, "WATCH": 0},
    }
    sampled_result: dict[str, Any] = {"anomalies_with_narratives": []}

    def execute_step(step_index: int, step_name: str, action: Any) -> Any:
        nonlocal steps_completed

        print_step_header(f"STEP {step_index} - {step_name}")
        t0 = time.time()
        result: Any = None

        try:
            result = action()
        except Exception:
            error_text = traceback.format_exc()
            failures.append(f"STEP {step_index} - {step_name} failed\n{error_text}")
            print(error_text)
        finally:
            elapsed = time.time() - t0
            label = f"STEP {step_index} - {step_name}"
            step_timings[label] = elapsed
            print(f"{label} timing: {elapsed:.2f}s")

            steps_completed += 1
            if pipeline_client is not None and run_id is not None:
                try:
                    update_pipeline_run(
                        pipeline_client,
                        run_id,
                        {"steps_completed": steps_completed},
                    )
                except Exception:
                    failures.append(
                        "PIPELINE_RUN_TRACKING update failed\n" + traceback.format_exc()
                    )

        return result

    execute_step(1, "FETCH REPORTS", step_fetch)
    execute_step(2, "BUILD TRENDS", step_build_trends)

    detect_result: dict[str, Any] = {"anomalies": [], "tier_counts": {"CRITICAL": 0, "ALERT": 0, "WATCH": 0}}
    detected = execute_step(3, "DETECT ANOMALIES", step_detect_anomalies)
    if isinstance(detected, dict):
        detect_result = detected

    sampled = execute_step(
        4,
        "SAMPLE NARRATIVES",
        lambda: step_sample_narratives(detect_result.get("anomalies", [])),
    )
    if isinstance(sampled, dict):
        sampled_result = sampled

    if pipeline_client is not None and has_anomaly_alerts:
        execute_step(
            5,
            "WRITE ANOMALY ALERTS",
            lambda: step_write_anomaly_alerts(
                pipeline_client,
                run_id,
                detect_result.get("anomalies", []),
                sampled_result,
            ),
        )
    else:
        print("STEP 5 - WRITE ANOMALY ALERTS skipped: client unavailable or table missing")

    if has_weekly_briefings:
        execute_step(
            6,
            "GENERATE WEEKLY BRIEFING",
            lambda: step_generate_weekly_briefing(run_id),
        )
    else:
        print_step_header("STEP 6 - GENERATE WEEKLY BRIEFING")
        print("STEP 6 skipped: weekly_briefings table missing")
        step_timings["STEP 6 - GENERATE WEEKLY BRIEFING"] = 0.0
        steps_completed += 1
    execute_step(7, "PURGE NARRATIVES", step_purge_narratives)
    execute_step(
        8,
        "FINAL REPORT",
        lambda: print_final_report(started_at, step_timings, detect_result, sampled_result, failures),
    )

    print_step_header("PIPELINE SUMMARY")
    if failures:
        print("One or more steps failed. Summary:")
        for failure in failures:
            print("-" * 78)
            print(failure)
    else:
        print("No step failures detected.")

    if pipeline_client is not None and run_id is not None and has_pipeline_runs:
        try:
            update_pipeline_run(
                pipeline_client,
                run_id,
                {
                    "status": "complete",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "steps_completed": steps_completed,
                },
            )
        except Exception:
            print("WARNING: failed to mark pipeline_runs status complete.")


def main() -> None:
    try:
        run_pipeline()
    except Exception:
        error_details = traceback.format_exc()
        print(error_details)

        try:
            client = get_supabase_client()
            if table_exists(client, "pipeline_runs"):
                client.table("pipeline_runs").update(
                    {
                        "status": "failed",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "error_details": error_details,
                    }
                ).eq("status", "running").execute()
        except Exception:
            print("WARNING: failed to write uncaught exception to pipeline_runs.")

        raise


if __name__ == "__main__":
    main()
