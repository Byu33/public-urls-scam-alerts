from __future__ import annotations

import unittest
from datetime import date, timedelta

import pandas as pd

from cfpb.detect_cfpb_anomalies import detect_cfpb_anomalies


def _weekly_rows(
    counts: list[int],
    *,
    start: date = date(2026, 1, 4),
    issue: str = "Fraud or scam",
    state: str = "CA",
) -> pd.DataFrame:
    rows = []
    for index, count in enumerate(counts):
        rows.append(
            {
                "week_ending": pd.Timestamp(start + timedelta(weeks=index)),
                "product": "Money transfer, virtual currency, or money service",
                "issue": issue,
                "state": state,
                "report_count": count,
            }
        )
    return pd.DataFrame(rows)


class CfpbAnomalyDetectionTests(unittest.TestCase):
    def test_skips_data_lagged_latest_week(self) -> None:
        df = _weekly_rows([9, 10, 11, 9, 10, 11, 9, 10, 16, 2])

        anomalies = detect_cfpb_anomalies(df)

        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["week_ending"], "2026-03-01")
        self.assertEqual(anomalies[0]["current_count"], 16)

    def test_allows_single_week_spike_above_lower_floor(self) -> None:
        df = _weekly_rows(
            [1, 2, 1, 2, 1, 2, 1, 2, 6],
            issue="Problem with a lender or other company charging your account",
            state="CT",
        )

        anomalies = detect_cfpb_anomalies(df)

        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["week_ending"], "2026-03-01")
        self.assertEqual(anomalies[0]["current_count"], 6)


if __name__ == "__main__":
    unittest.main()
