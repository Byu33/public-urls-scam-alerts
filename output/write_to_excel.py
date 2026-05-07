from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
OUTPUT_DIR = REPO_ROOT / "sharepoint_output"


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not fieldnames:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys or ["message"]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        if rows:
            writer.writerows(rows)


def _tier_rows(prefix: str, counts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"source": prefix, "alert_tier": tier, "count": int(counts.get(tier, 0) or 0)}
        for tier in ("CRITICAL", "ALERT", "WATCH")
    ]


def _briefing_markdown(
    builder: dict[str, Any],
    verifier: dict[str, Any],
    quality: dict[str, Any],
    output_status: str,
) -> str:
    data_summary = {
        "BBB records ingested": builder.get("data_summary", {}).get("bbb_records_ingested", 0),
        "CFPB records ingested": builder.get("data_summary", {}).get("cfpb_records_ingested", 0),
        "Local crime records": builder.get("data_summary", {}).get("local_crime_records", 0),
        "BBB anomalies": verifier.get("anomaly_summary", {}).get("bbb_anomalies_by_tier", {}),
        "CFPB anomalies": verifier.get("anomaly_summary", {}).get("cfpb_anomalies_by_tier", {}),
        "Cross source signals": quality.get("cross_source_signals", {}).get("count", 0),
    }
    lines = [
        "# Weekly Scam Intelligence Briefing",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Phase Status",
        f"- Builder: {builder.get('overall_status', 'UNKNOWN')}",
        f"- Verifier: {verifier.get('overall_status', 'UNKNOWN')}",
        f"- Data Quality: {quality.get('overall_status', 'UNKNOWN')}",
        f"- Output: {output_status}",
        "",
        "## Data Summary",
    ]
    for key, value in data_summary.items():
        lines.append(f"- {key}: {value}")

    warnings = []
    for report in (builder, verifier, quality):
        warnings.extend(report.get("warnings", []) or [])
        warnings.extend(report.get("issues", []) or [])
    if warnings:
        lines.extend(["", "## Warnings and Follow-up"])
        lines.extend(f"- {warning}" for warning in warnings)

    return "\n".join(lines) + "\n"


def write_outputs() -> dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    builder = _read_json(AGENTS_DIR / "builder_report.json")
    verifier = _read_json(AGENTS_DIR / "verifier_report.json")
    quality = _read_json(AGENTS_DIR / "quality_report.json")

    table_counts = [
        {"table": table, "row_count": count}
        for table, count in sorted((verifier.get("table_counts") or {}).items())
    ]
    _write_csv(OUTPUT_DIR / "Supabase_Table_Counts.csv", table_counts, ["table", "row_count"])

    _write_csv(
        OUTPUT_DIR / "BBB_Anomalies.csv",
        _tier_rows("BBB", verifier.get("anomaly_summary", {}).get("bbb_anomalies_by_tier", {})),
        ["source", "alert_tier", "count"],
    )
    _write_csv(
        OUTPUT_DIR / "CFPB_Anomalies.csv",
        _tier_rows("CFPB", verifier.get("anomaly_summary", {}).get("cfpb_anomalies_by_tier", {})),
        ["source", "alert_tier", "count"],
    )
    _write_csv(
        OUTPUT_DIR / "Cross_Source_Signals.csv",
        quality.get("cross_source_signals", {}).get("signals", []),
        ["signal_type", "description", "count"],
    )
    _write_csv(
        OUTPUT_DIR / "Pipeline_Phase_Status.csv",
        [
            {"phase": "Builder", "status": builder.get("overall_status", "UNKNOWN")},
            {"phase": "Verifier", "status": verifier.get("overall_status", "UNKNOWN")},
            {"phase": "Data Quality", "status": quality.get("overall_status", "UNKNOWN")},
            {"phase": "Output", "status": "PASS"},
        ],
        ["phase", "status"],
    )

    briefing_path = OUTPUT_DIR / "Weekly_Briefing.md"
    briefing_path.write_text(_briefing_markdown(builder, verifier, quality, "PASS"), encoding="utf-8")

    workbook_path = OUTPUT_DIR / "Scam_Intelligence_Briefing.xlsx"
    with pd.ExcelWriter(workbook_path, engine="openpyxl") as writer:
        pd.DataFrame(table_counts).to_excel(writer, sheet_name="Table Counts", index=False)
        pd.DataFrame(_tier_rows("BBB", verifier.get("anomaly_summary", {}).get("bbb_anomalies_by_tier", {}))).to_excel(
            writer, sheet_name="BBB Anomalies", index=False
        )
        pd.DataFrame(_tier_rows("CFPB", verifier.get("anomaly_summary", {}).get("cfpb_anomalies_by_tier", {}))).to_excel(
            writer, sheet_name="CFPB Anomalies", index=False
        )
        pd.DataFrame(quality.get("narrative_samples", [])).to_excel(writer, sheet_name="Narrative Samples", index=False)
        pd.DataFrame(quality.get("cross_source_signals", {}).get("signals", [])).to_excel(
            writer, sheet_name="Cross Signals", index=False
        )

    files = sorted(str(path.relative_to(REPO_ROOT)) for path in OUTPUT_DIR.iterdir() if path.is_file())
    result = {
        "overall_status": "PASS",
        "files": files,
        "excel_file": str(workbook_path.relative_to(REPO_ROOT)),
        "briefing_file": str(briefing_path.relative_to(REPO_ROOT)),
    }
    print(json.dumps(result, indent=2))
    return result


def main() -> dict[str, Any]:
    return write_outputs()


if __name__ == "__main__":
    main()
