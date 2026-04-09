from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from supabase import Client, create_client


PAGE_SIZE = 1000


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


def fetch_expired_records(client: Client, now_iso: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    start = 0

    while True:
        response = (
            client.table("bbb_scam_reports")
            .select("id,narrative_expires_at")
            .not_.is_("narrative", "null")
            .lt("narrative_expires_at", now_iso)
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    return rows


def batch_update_purge(client: Client, ids: list[str], purged_at_iso: str) -> int:
    if not ids:
        return 0

    total = 0
    for start in range(0, len(ids), PAGE_SIZE):
        batch = ids[start : start + PAGE_SIZE]
        response = (
            client.table("bbb_scam_reports")
            .update({"narrative": None, "narrative_purged_at": purged_at_iso})
            .in_("id", batch)
            .execute()
        )
        total += len(response.data or [])
    return total


def fetch_all_rows(client: Client) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    start = 0

    while True:
        response = (
            client.table("bbb_scam_reports")
            .select("id,narrative,narrative_expires_at,narrative_purged_at")
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    return rows


def print_verification_counts(client: Client, now_iso: str) -> None:
    all_rows = fetch_all_rows(client)
    total_records = len(all_rows)

    narrative_present = sum(1 for r in all_rows if r.get("narrative") is not None)
    narrative_purged = sum(1 for r in all_rows if r.get("narrative_purged_at") is not None)

    active_window = 0
    for row in all_rows:
        expires_at = row.get("narrative_expires_at")
        if expires_at is None:
            continue
        if str(expires_at) > now_iso:
            active_window += 1

    print("Verification counts:")
    print(f"- total records in table: {total_records}")
    print(f"- records with narrative still present: {narrative_present}")
    print(f"- records with narrative purged: {narrative_purged}")
    print(f"- records with narrative_expires_at in the future: {active_window}")


def _purge_table(
    client: Any,
    table_name: str,
    id_field: str,
    now_iso: str,
    dry_run: bool,
) -> int:
    """
    Generic purge: find rows where narrative is not null and narrative_expires_at < now,
    then null out narrative and set narrative_purged_at.

    Returns number of rows purged (0 in dry-run mode).
    """
    rows: list[dict[str, Any]] = []
    start = 0

    while True:
        try:
            response = (
                client.table(table_name)
                .select(f"{id_field},narrative_expires_at")
                .not_.is_("narrative", "null")
                .lt("narrative_expires_at", now_iso)
                .range(start, start + PAGE_SIZE - 1)
                .execute()
            )
        except Exception as exc:
            code = getattr(exc, "code", None)
            message = str(exc)
            if code == "PGRST205" or "Could not find the table" in message:
                return 0
            raise
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    ids = [str(r.get(id_field)) for r in rows if r.get(id_field) is not None]
    oldest = None
    if rows:
        oldest = min(
            str(r.get("narrative_expires_at"))
            for r in rows
            if r.get("narrative_expires_at") is not None
        )

    print(f"  [{table_name}] records to purge: {len(ids)}  oldest: {oldest or 'N/A'}")

    if dry_run or not ids:
        return 0

    purged_at_iso = datetime.now(timezone.utc).isoformat()
    total_purged = 0
    for start in range(0, len(ids), PAGE_SIZE):
        batch = ids[start : start + PAGE_SIZE]
        response = (
            client.table(table_name)
            .update({"narrative": None, "narrative_purged_at": purged_at_iso})
            .in_(id_field, batch)
            .execute()
        )
        total_purged += len(response.data or [])
    return total_purged


def run_purge(dry_run: bool) -> int:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    client = get_supabase_client()

    # ── BBB narratives ─────────────────────────────────────────────────────────
    expired_rows = fetch_expired_records(client, now_iso)
    expired_ids = [str(r.get("id")) for r in expired_rows if r.get("id") is not None]

    oldest_expires = None
    if expired_rows:
        oldest_expires = min(
            str(r.get("narrative_expires_at")) for r in expired_rows if r.get("narrative_expires_at") is not None
        )

    print("BBB dry run summary:")
    print(f"- records that would be purged: {len(expired_ids)}")
    print(f"- oldest narrative_expires_at among them: {oldest_expires or 'N/A'}")

    if dry_run:
        # Also show CFPB dry-run count
        cfpb_count = _purge_table(client, "cfpb_complaints", "id", now_iso, dry_run=True)
        print(f"CFPB narratives that would be purged: {cfpb_count}")
        print("Dry run mode enabled (--dry-run). Skipping actual purge.")
        return 0

    bbb_purged = 0
    if expired_ids:
        purged_at_iso = datetime.now(timezone.utc).isoformat()
        try:
            bbb_purged = batch_update_purge(client, expired_ids, purged_at_iso)
        except Exception as exc:
            print(f"BBB purge update operation failed: {exc}")
            return 1
        print(f"BBB narratives purged: {bbb_purged}")
        print_verification_counts(client, datetime.now(timezone.utc).isoformat())
    else:
        print("BBB: nothing to purge.")

    # ── CFPB narratives ────────────────────────────────────────────────────────
    try:
        cfpb_purged = _purge_table(client, "cfpb_complaints", "id", now_iso, dry_run=False)
        print(f"CFPB narratives purged: {cfpb_purged}")
    except Exception as exc:
        print(f"CFPB purge failed: {exc}")
        # Don't return 1 — BBB purge succeeded; CFPB failure is non-fatal

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Purge expired narratives from bbb_scam_reports")
    parser.add_argument("--dry-run", action="store_true", help="Print dry run summary and skip update")
    args = parser.parse_args()

    try:
        return run_purge(dry_run=args.dry_run)
    except Exception as exc:
        print(f"purge_narratives.py failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
