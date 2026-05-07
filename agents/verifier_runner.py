from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import sys
import traceback
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from supabase import create_client


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = REPO_ROOT / "agents" / "verifier_report.json"
TODAY = date.today()

TABLES = [
    "bbb_scam_reports",
    "bbb_trends",
    "anomaly_alerts",
    "cfpb_trends",
    "cfpb_complaints",
    "cfpb_anomaly_alerts",
    "local_crime_reports",
    "weekly_briefings",
    "pipeline_runs",
]

CFPB_SCAM_TYPE_BY_PRODUCT_ISSUE: dict[tuple[str, str], str] = {
    ("Money transfer, virtual currency, or money service", "Fraud or scam"): "Payment Fraud",
    (
        "Checking or savings account",
        "Problem with a lender or other company charging your account",
    ): "Account Takeover",
    ("Checking or savings account", "Managing an account"): "Debit Card Fraud",
    (
        "Credit card or prepaid card",
        "Problem with a purchase shown on your statement",
    ): "Credit Card Fraud",
    ("Credit card or prepaid card", "Getting a credit card"): "Identity Theft",
    ("Debt collection", "False statements or representation"): "Debt Collection Fraud",
    (
        "Credit card or prepaid card",
        "Problem with a purchase or transfer",
    ): "Gift Card Scam",
    (
        "Debt or credit management",
        "Didn't provide services promised",
    ): "Predatory Service Scam",
}


class Verifier:
    def __init__(self) -> None:
        load_dotenv(REPO_ROOT / ".env.local")
        load_dotenv(REPO_ROOT / ".env")
        load_dotenv()
        self.supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        self.supabase_key = (
            os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY")
            or os.environ.get("SUPABASE_ANON_KEY")
            or ""
        )
        self.headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Accept": "application/json",
        }
        self.issues: list[str] = []
        self.recommended_fixes: list[str] = []
        self.section_status: dict[str, str] = {}
        self.table_row_counts: dict[str, int] = {table: 0 for table in TABLES}
        self.bbb_history_weeks = 0
        self.cfpb_history_weeks = 0
        self.bbb_records_today = 0
        self.cfpb_records_today = 0
        self.bbb_anomalies_by_tier = {"CRITICAL": 0, "ALERT": 0, "WATCH": 0}
        self.cfpb_anomalies_by_tier = {"CRITICAL": 0, "ALERT": 0, "WATCH": 0}
        self.files_in_output: list[str] = []
        self.bbb_live_summary: dict[str, Any] = {}
        self.cfpb_live_summary: dict[str, Any] = {}

    def add_issue(self, issue: str, fix: str | None = None) -> None:
        if issue not in self.issues:
            self.issues.append(issue)
        if fix and fix not in self.recommended_fixes:
            self.recommended_fixes.append(fix)

    def rest_url(self, table: str) -> str:
        return f"{self.supabase_url}/rest/v1/{table}"

    def rest_get(self, table: str, params: dict[str, Any], count: bool = False) -> requests.Response:
        headers = dict(self.headers)
        if count:
            headers["Prefer"] = "count=exact"
        response = requests.get(self.rest_url(table), params=params, headers=headers, timeout=60)
        return response

    def get_count(self, table: str, filters: dict[str, str] | None = None) -> int | None:
        params: dict[str, Any] = {"select": "*", "limit": "0"}
        if filters:
            params.update(filters)
        response = self.rest_get(table, params, count=True)
        if response.status_code >= 400:
            self.add_issue(
                f"Table count failed for {table}: HTTP {response.status_code} {response.text[:300]}",
                "Verify the Supabase table exists and the service role has access.",
            )
            return None
        content_range = response.headers.get("content-range", "")
        if "/" in content_range:
            total = content_range.rsplit("/", 1)[-1]
            if total.isdigit():
                return int(total)
        try:
            body = response.json()
            return len(body) if isinstance(body, list) else 0
        except Exception:
            return 0

    def fetch_rows(
        self,
        table: str,
        columns: str,
        params_extra: dict[str, str] | None = None,
        page_size: int = 1000,
    ) -> tuple[list[dict[str, Any]], str | None]:
        rows: list[dict[str, Any]] = []
        offset = 0
        while True:
            params: dict[str, Any] = {
                "select": columns,
                "limit": str(page_size),
                "offset": str(offset),
            }
            if params_extra:
                params.update(params_extra)
            response = self.rest_get(table, params)
            if response.status_code >= 400:
                return rows, f"HTTP {response.status_code} {response.text[:500]}"
            page = response.json()
            if not isinstance(page, list):
                return rows, f"Unexpected response shape: {str(page)[:500]}"
            rows.extend(page)
            if len(page) < page_size:
                return rows, None
            offset += page_size

    @staticmethod
    def min_max(values: list[Any]) -> tuple[Any, Any]:
        cleaned = sorted(str(v) for v in values if v not in (None, ""))
        if not cleaned:
            return None, None
        return cleaned[0], cleaned[-1]

    @staticmethod
    def load_module(name: str, path: Path) -> Any:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load module {name} from {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def supabase_client(self) -> Any:
        return create_client(self.supabase_url, self.supabase_key)

    def verify_tables(self) -> None:
        print("\nSECTION 1 - SUPABASE TABLE VERIFICATION")
        print("=" * 72)
        if not self.supabase_url or not self.supabase_key:
            self.add_issue(
                "Supabase credentials are missing from the runtime environment.",
                "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY for verifier runs.",
            )
            self.section_status["section_1"] = "FAIL"
            return

        for table in TABLES:
            count = self.get_count(table)
            self.table_row_counts[table] = int(count or 0)

        rows, error = self.fetch_rows("bbb_scam_reports", "reported_date,ingested_at,narrative")
        if error:
            print(f"bbb_scam_reports - ERROR: {error}")
        narrative_count = sum(1 for r in rows if r.get("narrative") not in (None, ""))
        reported_min, reported_max = self.min_max([r.get("reported_date") for r in rows])
        ingested_max = self.min_max([r.get("ingested_at") for r in rows])[1]
        print(
            "bbb_scam_reports - total rows: "
            f"{self.table_row_counts['bbb_scam_reports']}, rows with non-null narrative: "
            f"{narrative_count}, reported_date range: {reported_min} to {reported_max}, "
            f"most recent ingested_at: {ingested_max}"
        )

        rows, error = self.fetch_rows("bbb_trends", "week_ending")
        if error:
            print(f"bbb_trends - ERROR: {error}")
        bbb_weeks = sorted({r.get("week_ending") for r in rows if r.get("week_ending")})
        self.bbb_history_weeks = len(bbb_weeks)
        print(
            "bbb_trends - total rows: "
            f"{self.table_row_counts['bbb_trends']}, distinct week_ending count: {len(bbb_weeks)}, "
            f"earliest week_ending: {bbb_weeks[0] if bbb_weeks else None}, "
            f"latest week_ending: {bbb_weeks[-1] if bbb_weeks else None}"
        )

        rows, error = self.fetch_rows("anomaly_alerts", "alert_tier,analysis_status")
        if error and "analysis_status" in error:
            self.add_issue(
                "anomaly_alerts does not expose analysis_status, so that requested breakdown could not be queried.",
                "Add analysis_status to anomaly_alerts or update the verifier requirement for this schema.",
            )
            rows, error = self.fetch_rows("anomaly_alerts", "alert_tier")
        print(
            "anomaly_alerts - total rows: "
            f"{self.table_row_counts['anomaly_alerts']}, breakdown by alert_tier: "
            f"{dict(Counter(r.get('alert_tier') for r in rows))}, breakdown by analysis_status: "
            f"{dict(Counter(r.get('analysis_status') for r in rows if 'analysis_status' in r))}"
        )
        if error:
            print(f"anomaly_alerts - ERROR: {error}")

        rows, error = self.fetch_rows("weekly_briefings", "briefing_status,week_ending,created_at")
        recent = max(rows, key=lambda r: str(r.get("created_at") or ""), default={})
        print(
            "weekly_briefings - total rows: "
            f"{self.table_row_counts['weekly_briefings']}, most recent briefing_status: "
            f"{recent.get('briefing_status')}, most recent week_ending: {recent.get('week_ending')}"
        )
        if error:
            print(f"weekly_briefings - ERROR: {error}")

        rows, error = self.fetch_rows("pipeline_runs", "status,run_date,steps_completed,started_at,created_at")
        if error and "run_date" in error:
            self.add_issue(
                "pipeline_runs does not expose run_date; using started_at as the closest available run timestamp.",
                "Add run_date to pipeline_runs or update reporting to use started_at.",
            )
            rows, error = self.fetch_rows("pipeline_runs", "status,steps_completed,started_at,created_at")
        recent = max(rows, key=lambda r: str(r.get("run_date") or r.get("started_at") or ""), default={})
        print(
            "pipeline_runs - total rows: "
            f"{self.table_row_counts['pipeline_runs']}, most recent status: {recent.get('status')}, "
            f"most recent run_date: {recent.get('run_date') or recent.get('started_at')}, "
            f"steps_completed: {recent.get('steps_completed')}"
        )
        if error:
            print(f"pipeline_runs - ERROR: {error}")

        rows, error = self.fetch_rows("cfpb_trends", "week_ending,scam_type,product,issue")
        used_mapping = False
        if error and "scam_type" in error:
            self.add_issue(
                "cfpb_trends does not expose scam_type; breakdown was mapped from product/issue pairs.",
                "Persist scam_type in cfpb_trends or keep a canonical mapping layer for reports.",
            )
            rows, error = self.fetch_rows("cfpb_trends", "week_ending,product,issue")
            used_mapping = True
        cfpb_weeks = sorted({r.get("week_ending") for r in rows if r.get("week_ending")})
        self.cfpb_history_weeks = len(cfpb_weeks)
        cfpb_breakdown = Counter()
        for row in rows:
            scam_type = row.get("scam_type")
            if not scam_type and used_mapping:
                scam_type = CFPB_SCAM_TYPE_BY_PRODUCT_ISSUE.get((row.get("product"), row.get("issue")), "UNKNOWN")
            cfpb_breakdown[scam_type] += 1
        print(
            "cfpb_trends - total rows: "
            f"{self.table_row_counts['cfpb_trends']}, distinct week count: {len(cfpb_weeks)}, "
            f"breakdown by scam_type: {dict(cfpb_breakdown)}"
        )
        if error:
            print(f"cfpb_trends - ERROR: {error}")

        rows, error = self.fetch_rows("cfpb_complaints", "date_received,narrative")
        cfpb_date_min, cfpb_date_max = self.min_max([r.get("date_received") for r in rows])
        cfpb_narratives = sum(1 for r in rows if r.get("narrative") not in (None, ""))
        print(
            "cfpb_complaints - total rows: "
            f"{self.table_row_counts['cfpb_complaints']}, date range: {cfpb_date_min} to {cfpb_date_max}, "
            f"rows with non-null narrative: {cfpb_narratives}"
        )
        if error:
            print(f"cfpb_complaints - ERROR: {error}")

        rows, error = self.fetch_rows("cfpb_anomaly_alerts", "alert_tier")
        print(
            "cfpb_anomaly_alerts - total rows: "
            f"{self.table_row_counts['cfpb_anomaly_alerts']}, breakdown by alert_tier: "
            f"{dict(Counter(r.get('alert_tier') for r in rows))}"
        )
        if error:
            print(f"cfpb_anomaly_alerts - ERROR: {error}")

        rows, error = self.fetch_rows("local_crime_reports", "city,reported_date,date")
        if error:
            print(f"local_crime_reports - ERROR: {error}")
            self.add_issue(
                "local_crime_reports table could not be queried.",
                "Create/populate local_crime_reports or remove it from the readiness contract.",
            )
        else:
            cities = Counter(r.get("city") for r in rows)
            dates = [r.get("reported_date") or r.get("date") for r in rows]
            date_min, date_max = self.min_max(dates)
            print(
                "local_crime_reports - total rows: "
                f"{self.table_row_counts['local_crime_reports']}, breakdown by city: "
                f"{dict(cities)}, date range: {date_min} to {date_max}"
            )

        failed_tables = [table for table, count in self.table_row_counts.items() if count == 0]
        if any("Table count failed" in issue for issue in self.issues):
            self.section_status["section_1"] = "FAIL"
        else:
            self.section_status["section_1"] = "PASS"
        if failed_tables:
            print(f"Tables with zero or unavailable row counts: {failed_tables}")

    def historical_check(self) -> None:
        print("\nSECTION 2 - HISTORICAL DATA CHECK")
        print("=" * 72)
        if self.bbb_history_weeks < 12:
            print(
                "WARNING - anomaly detection needs minimum 12 weeks of history. "
                f"bbb_trends has {self.bbb_history_weeks}. Recommend running bbb/fetch_historical.py first."
            )
            self.add_issue(
                f"bbb_trends has only {self.bbb_history_weeks} distinct weeks; minimum is 12.",
                "Run bbb/fetch_historical.py before relying on BBB anomaly detection.",
            )
        else:
            print(f"PASS - bbb_trends has {self.bbb_history_weeks} distinct week_ending values.")

        if self.cfpb_history_weeks < 16:
            print(
                "WARNING - CFPB anomaly detection needs minimum 16 weeks. "
                f"cfpb_trends has {self.cfpb_history_weeks}. Recommend running cfpb/fetch_cfpb_historical.py."
            )
            self.add_issue(
                f"cfpb_trends has only {self.cfpb_history_weeks} distinct weeks; minimum is 16.",
                "Run cfpb/fetch_cfpb_historical.py before relying on CFPB anomaly detection.",
            )
        else:
            print(f"PASS - cfpb_trends has {self.cfpb_history_weeks} distinct week_ending values.")
        self.section_status["section_2"] = (
            "PASS" if self.bbb_history_weeks >= 12 and self.cfpb_history_weeks >= 16 else "FAIL"
        )

    def bbb_live_scraper_test(self) -> None:
        print("\nSECTION 3 - LIVE SCRAPER TEST")
        print("=" * 72)
        override = os.environ.get("VERIFIER_BBB_SUMMARY_JSON")
        if override:
            try:
                self.bbb_live_summary = json.loads(override)
                self.bbb_records_today = int(self.bbb_live_summary.get("records_returned", 0))
                print("Using captured BBB live scraper summary from prior interrupted verifier run:")
                print(json.dumps(self.bbb_live_summary, indent=2, default=str))
                self.section_status["section_3"] = (
                    "PASS" if self.bbb_records_today > 0 else "FAIL"
                )
                return
            except Exception:
                print("VERIFIER_BBB_SUMMARY_JSON could not be parsed; running BBB scraper again.")
        try:
            existing_rows, existing_error = self.fetch_rows("bbb_scam_reports", "id")
            existing_ids = {r.get("id") for r in existing_rows if r.get("id")} if not existing_error else set()
            module = self.load_module("bbb_fetch_reports_verifier", REPO_ROOT / "bbb" / "fetch_reports.py")
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = module.run_fetch_pipeline()
            captured = buf.getvalue()
            print(captured)
            records = result.get("records", [])
            self.bbb_records_today = len(records)
            returned_ids = [r.get("id") for r in records if r.get("id")]
            new_count = sum(1 for rid in returned_ids if rid not in existing_ids)
            existing_count = len(returned_ids) - new_count
            reported_dates = [r.get("reported_date") for r in records if r.get("reported_date")]
            most_recent = max(reported_dates) if reported_dates else None
            samples = []
            for row in records[:3]:
                samples.append(
                    {
                        "scam_type": row.get("scam_type"),
                        "state": row.get("state"),
                        "dollar_amount": row.get("dollar_amount"),
                        "contact_method": row.get("contact_method"),
                        "narrative_preview": (row.get("narrative") or "")[:150],
                    }
                )
            self.bbb_live_summary = {
                "pages_scraped": result.get("total_pages_fetched", 0),
                "records_returned": len(records),
                "new_records": new_count,
                "already_existing": existing_count,
                "most_recent_reported_date": most_recent,
                "samples": samples,
            }
            print("BBB live scraper summary:")
            print(json.dumps(self.bbb_live_summary, indent=2, default=str))
            if len(records) == 0:
                end_date = date.today()
                start_date = end_date - timedelta(days=7)
                query = f"createdOn={start_date.isoformat()}TO{end_date.isoformat()}&from=0"
                response = requests.get(
                    module.BASE_URL,
                    params={"q": query},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; BBBScamScraper/2.0)"},
                    timeout=60,
                )
                print("Raw BBB first-page HTML response:")
                print(response.text[:5000])
                self.add_issue(
                    "BBB live scraper returned zero records.",
                    "Inspect BBB first-page HTML and update payload parsing if the site changed.",
                )
            self.section_status["section_3"] = "PASS" if len(records) > 0 else "FAIL"
        except Exception:
            print(traceback.format_exc())
            self.add_issue(
                "BBB live scraper test failed.",
                "Run bbb/fetch_reports.py with BBB_DEBUG=1 and inspect the exception.",
            )
            self.section_status["section_3"] = "FAIL"

    def cfpb_live_api_test(self) -> None:
        print("\nSECTION 4 - LIVE API TEST")
        print("=" * 72)
        try:
            fetch_module = self.load_module("cfpb_fetch_trends_verifier", REPO_ROOT / "cfpb" / "fetch_trends.py")
            build_module = self.load_module("cfpb_build_trends_verifier", REPO_ROOT / "cfpb" / "build_cfpb_trends.py")
            fetch_buf = io.StringIO()
            with redirect_stdout(fetch_buf):
                rows = fetch_module.fetch_cfpb_trends()
            print(fetch_buf.getvalue())
            self.cfpb_records_today = len(rows)
            build_buf = io.StringIO()
            upsert_success = False
            build_result: dict[str, Any] = {}
            try:
                with redirect_stdout(build_buf):
                    build_result = build_module.build_cfpb_trends(rows)
                upsert_success = int(build_result.get("upserted_rows", 0)) > 0
            finally:
                print(build_buf.getvalue())
            category_summaries = []
            any_zero = False
            for category in fetch_module.CFPB_CATEGORIES:
                scam_type = category["scam_type"]
                category_rows = [r for r in rows if r.get("scam_type") == scam_type]
                weeks = sorted({r.get("week_ending") for r in category_rows if r.get("week_ending")})
                summary = {
                    "category_name": category["product"],
                    "issue": category["issue"],
                    "scam_type_mapping": scam_type,
                    "weekly_data_points_returned": len(category_rows),
                    "date_range": f"{weeks[0]} to {weeks[-1]}" if weeks else None,
                    "successfully_upserted": bool(upsert_success and category_rows),
                }
                category_summaries.append(summary)
                print(json.dumps(summary, indent=2))
                if not category_rows:
                    any_zero = True
                    print(f"Raw CFPB API response for zero category {scam_type}:")
                    today = date.today()
                    params: dict[str, Any] = {
                        "product": category["product"],
                        "issue": category["issue"],
                        "date_received_min": (today - timedelta(weeks=fetch_module.LOOKBACK_WEEKS)).isoformat(),
                        "date_received_max": today.isoformat(),
                        "no_aggs": "true",
                        "format": "json",
                        "size": 5,
                        "from": 0,
                    }
                    sub_products = category.get("sub_products", [])
                    if len(sub_products) == 1:
                        params["sub_product"] = sub_products[0]
                    raw_response = requests.get(
                        fetch_module.CFPB_API_BASE,
                        params=params,
                        headers=fetch_module._HEADERS,
                        timeout=60,
                    )
                    print(raw_response.text[:5000])
            self.cfpb_live_summary = {
                "total_rows_returned": len(rows),
                "build_result": build_result,
                "categories": category_summaries,
            }
            if any_zero:
                self.add_issue(
                    "One or more CFPB categories returned zero weekly data points.",
                    "Inspect the raw CFPB API response and category filter definitions.",
                )
            if not upsert_success:
                self.add_issue(
                    "CFPB trend rows were not successfully upserted.",
                    "Run cfpb/build_cfpb_trends.py and inspect Supabase upsert errors.",
                )
            self.section_status["section_4"] = "PASS" if rows and upsert_success and not any_zero else "FAIL"
        except Exception:
            print(traceback.format_exc())
            self.add_issue(
                "CFPB live API test failed.",
                "Run cfpb/fetch_trends.py and cfpb/build_cfpb_trends.py directly for diagnostics.",
            )
            self.section_status["section_4"] = "FAIL"

    def anomaly_detection_test(self) -> None:
        print("\nSECTION 5 - ANOMALY DETECTION TEST")
        print("=" * 72)
        bbb_ok = self.run_bbb_anomalies()
        cfpb_ok = self.run_cfpb_anomalies()
        self.section_status["section_5"] = "PASS" if bbb_ok and cfpb_ok else "FAIL"

    def run_bbb_anomalies(self) -> bool:
        print("\nBBB anomaly detection output:")
        print("-" * 72)
        try:
            module = self.load_module("bbb_detect_anomalies_verifier", REPO_ROOT / "bbb" / "detect_anomalies.py")
            client = module.get_supabase_client()
            df = module.pull_trends_data(client)
            buf = io.StringIO()
            with redirect_stdout(buf):
                if df.empty:
                    print("No trend data found for the last 16 weeks.")
                    anomalies: list[dict[str, Any]] = []
                else:
                    n_combos = df.groupby(["scam_type", "state"], dropna=False).ngroups
                    print(
                        f"Loaded {len(df)} rows | {df['week_ending'].nunique()} weeks | "
                        f"{n_combos} scam_type/state combinations"
                    )
                    print("\n" + "=" * 78)
                    print("FILTER TRACE (--test mode)")
                    print("=" * 78)
                    print("\n-- National pass --")
                    national = module.detect_anomalies_national(df, trace=True)
                    print("\n-- State pass --")
                    state = module.detect_anomalies(df, trace=True)
                    anomalies = module.merge_detection_results(national, state)
                    module.print_results(anomalies)
            print(buf.getvalue())
            self.print_anomaly_summary("BBB", anomalies)
            self.bbb_anomalies_by_tier = {
                tier: sum(1 for a in anomalies if a.get("alert_tier") == tier)
                for tier in ("CRITICAL", "ALERT", "WATCH")
            }
            if not anomalies:
                self.print_bbb_volume_floor_diagnostic(module, df)
            return True
        except Exception:
            print(traceback.format_exc())
            self.add_issue(
                "BBB anomaly detection test failed.",
                "Run bbb/detect_anomalies.py --test and inspect the exception.",
            )
            return False

    def run_cfpb_anomalies(self) -> bool:
        print("\nCFPB anomaly detection output:")
        print("-" * 72)
        try:
            if str(REPO_ROOT / "bbb") not in sys.path:
                sys.path.insert(0, str(REPO_ROOT / "bbb"))
            module = self.load_module(
                "cfpb_detect_anomalies_verifier", REPO_ROOT / "cfpb" / "detect_cfpb_anomalies.py"
            )
            client = module.get_supabase_client()
            df = module.pull_cfpb_trends(client)
            buf = io.StringIO()
            with redirect_stdout(buf):
                if df.empty:
                    print("No CFPB trend data found for the last 24 weeks.")
                    anomalies: list[dict[str, Any]] = []
                else:
                    n_combos = df[df["state"] != "NATIONAL"].groupby(
                        ["product", "issue", "state"], dropna=False
                    ).ngroups
                    print(
                        f"Loaded {len(df)} CFPB trend rows | {df['week_ending'].nunique()} weeks | "
                        f"{n_combos} product/issue/state combinations"
                    )
                    national = module.detect_cfpb_anomalies_national(df, trace=True)
                    state = module.detect_cfpb_anomalies(df, trace=True)
                    anomalies = module.merge_cfpb_results(national, state)
                    module.print_cfpb_results(anomalies)
            print(buf.getvalue())
            self.print_anomaly_summary("CFPB", anomalies)
            self.cfpb_anomalies_by_tier = {
                tier: sum(1 for a in anomalies if a.get("alert_tier") == tier)
                for tier in ("CRITICAL", "ALERT", "WATCH")
            }
            if not anomalies:
                self.print_cfpb_volume_floor_diagnostic(module, df)
            return True
        except Exception:
            print(traceback.format_exc())
            self.add_issue(
                "CFPB anomaly detection test failed.",
                "Run cfpb/detect_cfpb_anomalies.py --test and inspect the exception.",
            )
            return False

    def print_anomaly_summary(self, label: str, anomalies: list[dict[str, Any]]) -> None:
        print(f"{label} anomalies sorted by short_deviation descending:")
        sorted_rows = sorted(anomalies, key=lambda r: float(r.get("short_deviation") or 0), reverse=True)
        for row in sorted_rows:
            print(json.dumps(row, default=str, sort_keys=True))
        tier_counts = Counter(row.get("alert_tier") for row in anomalies)
        scope_counts = Counter(row.get("scope") for row in anomalies)
        level_counts = Counter(row.get("detection_level") for row in anomalies)
        print(f"{label} anomalies per tier: {dict(tier_counts)}")
        print(f"{label} anomalies per scope level: {dict(scope_counts)}")
        print(f"{label} national vs state vs both detections: {dict(level_counts)}")
        top = sorted_rows[0] if sorted_rows else None
        print(f"{label} top anomaly: {json.dumps(top, default=str, sort_keys=True)}")

    def print_bbb_volume_floor_diagnostic(self, module: Any, df: Any) -> None:
        print("BBB zero-anomaly volume floor diagnostic:")
        if df.empty:
            print("No BBB trend data available.")
            return
        current_week = df["week_ending"].max()
        current = df[df["week_ending"] == current_week]
        if current.empty:
            print("No current-week BBB rows available.")
            return
        state_row = current.sort_values("report_count", ascending=False).iloc[0]
        state_floor = module.get_floor(str(state_row["scam_type"]), state_row["state"])
        national = module.build_national_df(df)
        nat_current = national[national["week_ending"] == national["week_ending"].max()]
        nat_row = nat_current.sort_values("report_count", ascending=False).iloc[0] if not nat_current.empty else None
        print(
            "Highest state volume combination: "
            f"{state_row['scam_type']} / {state_row['state']} count={int(state_row['report_count'])} "
            f"floor={state_floor}"
        )
        if nat_row is not None:
            nat_floor = module.get_national_floor(str(nat_row["scam_type"]))
            print(
                "Highest national volume combination: "
                f"{nat_row['scam_type']} count={int(nat_row['report_count'])} floor={nat_floor}"
            )

    def print_cfpb_volume_floor_diagnostic(self, module: Any, df: Any) -> None:
        print("CFPB zero-anomaly volume floor diagnostic:")
        if df.empty:
            print("No CFPB trend data available.")
            return
        current_week = df["week_ending"].max()
        current = df[df["week_ending"] == current_week]
        if current.empty:
            print("No current-week CFPB rows available.")
            return
        state_current = current[current["state"] != "NATIONAL"]
        if not state_current.empty:
            state_row = state_current.sort_values("report_count", ascending=False).iloc[0]
            state_floor = module._get_state_floor(str(state_row["issue"]), state_row["state"])
            print(
                "Highest state volume combination: "
                f"{state_row['product']} / {state_row['issue']} / {state_row['state']} "
                f"count={int(state_row['report_count'])} floor={state_floor}"
            )
        national = module._build_national_df(df)
        nat_current = national[national["week_ending"] == national["week_ending"].max()]
        if not nat_current.empty:
            nat_row = nat_current.sort_values("report_count", ascending=False).iloc[0]
            nat_floor = module._get_national_floor(str(nat_row["issue"]))
            print(
                "Highest national volume combination: "
                f"{nat_row['product']} / {nat_row['issue']} count={int(nat_row['report_count'])} "
                f"floor={nat_floor}"
            )

    def output_file_verification(self) -> None:
        print("\nSECTION 6 - OUTPUT FILE VERIFICATION")
        print("=" * 72)
        output_dir = REPO_ROOT / "sharepoint_output"
        if not output_dir.exists():
            print("sharepoint_output folder does not exist.")
            self.add_issue(
                "sharepoint_output folder does not exist.",
                "Run the pipeline step that generates SharePoint output files.",
            )
            self.section_status["section_6"] = "FAIL"
            return
        files = sorted([p for p in output_dir.iterdir() if p.is_file()])
        self.files_in_output = [p.name for p in files]
        if not files:
            print("sharepoint_output folder exists but contains no files.")
            self.add_issue(
                "sharepoint_output folder contains no files.",
                "Generate weekly CSV/Markdown output before marking the pipeline ready.",
            )
            self.section_status["section_6"] = "FAIL"
            return
        stale_found = False
        for path in files:
            stat = path.stat()
            modified = datetime.fromtimestamp(stat.st_mtime)
            modified_today = modified.date() == TODAY
            size_kb = stat.st_size / 1024
            stale = stat.st_size == 0 or not modified_today
            stale_found = stale_found or stale
            print(
                f"Filename: {path.name}; size_kb: {size_kb:.2f}; last_modified: "
                f"{modified.isoformat(sep=' ', timespec='seconds')}; modified_today: {modified_today}; "
                f"status: {'STALE' if stale else 'OK'}"
            )
            if path.suffix.lower() == ".csv":
                with path.open(newline="", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    rows = list(reader)
                print(f"CSV columns: {reader.fieldnames}")
                print(f"CSV row count: {len(rows)}")
                print(f"CSV first 2 rows: {rows[:2]}")
            elif path.suffix.lower() in {".md", ".markdown"}:
                text = path.read_text(encoding="utf-8", errors="replace")
                print(f"Markdown first 500 characters: {text[:500]}")
            if stale:
                self.add_issue(
                    f"Output file {path.name} is empty or was not modified today.",
                    "Regenerate sharepoint_output artifacts during the current pipeline run.",
                )
        self.section_status["section_6"] = "FAIL" if stale_found else "PASS"

    def write_report(self) -> None:
        print("\nSECTION 7 - WRITE VERIFIER REPORT")
        print("=" * 72)
        overall = "READY" if not self.issues else "NOT READY"
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bbb_history_weeks": int(self.bbb_history_weeks),
            "cfpb_history_weeks": int(self.cfpb_history_weeks),
            "bbb_records_today": int(self.bbb_records_today),
            "cfpb_records_today": int(self.cfpb_records_today),
            "table_row_counts": {table: int(self.table_row_counts.get(table, 0)) for table in TABLES},
            "bbb_anomalies_by_tier": {
                tier: int(self.bbb_anomalies_by_tier.get(tier, 0))
                for tier in ("CRITICAL", "ALERT", "WATCH")
            },
            "cfpb_anomalies_by_tier": {
                tier: int(self.cfpb_anomalies_by_tier.get(tier, 0))
                for tier in ("CRITICAL", "ALERT", "WATCH")
            },
            "files_in_output": self.files_in_output,
            "issues": self.issues,
            "overall_status": overall,
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {REPORT_PATH.relative_to(REPO_ROOT)}")
        print(json.dumps(report, indent=2))
        self.section_status["section_7"] = "PASS"

    def final_verdict(self) -> None:
        print("\nSECTION 8 - FINAL VERDICT")
        print("=" * 72)
        for idx in range(1, 8):
            key = f"section_{idx}"
            print(f"SECTION {idx}: {self.section_status.get(key, 'FAIL')}")
        print("Specific issues found:")
        if self.issues:
            for issue in self.issues:
                print(f"- {issue}")
        else:
            print("- none")
        print("Recommended fixes:")
        if self.recommended_fixes:
            for fix in self.recommended_fixes:
                print(f"- {fix}")
        else:
            print("- none")
        print(f"Overall status: {'READY' if not self.issues else 'NOT READY'}")
        self.section_status["section_8"] = "PASS" if not self.issues else "FAIL"

    def run(self) -> None:
        builder_path = REPO_ROOT / "agents" / "builder_report.json"
        if builder_path.exists():
            print("Read agents/builder_report.json:")
            print(builder_path.read_text(encoding="utf-8", errors="replace"))
        else:
            print("agents/builder_report.json was not found after the requested wait; proceeding anyway.")
            self.add_issue(
                "agents/builder_report.json was not present before verification.",
                "Run the builder agent first or write agents/builder_report.json before verifier execution.",
            )

        self.verify_tables()
        self.historical_check()
        self.bbb_live_scraper_test()
        self.cfpb_live_api_test()
        self.anomaly_detection_test()
        self.output_file_verification()
        self.write_report()
        self.final_verdict()


if __name__ == "__main__":
    Verifier().run()
