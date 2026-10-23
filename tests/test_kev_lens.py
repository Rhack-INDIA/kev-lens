#!/usr/bin/env python3
"""Unit tests for kev-lens. Run: python3 -m unittest discover -s tests -v"""
import sys, unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import kev_lens as k


def V(cve, added, due, vendor="Acme", product="Widget"):
    return {"cveID": cve, "dateAdded": added, "dueDate": due,
            "vendorProject": vendor, "product": product}


FIXTURE = [
    V("CVE-2008-4250", "2026-01-10", "2026-01-13"),   # 3-day tier, resurrected (18y)
    V("CVE-2024-1111", "2026-01-10", "2026-01-24"),   # 14-day tier
    V("CVE-2026-2222", "2026-02-01", "2026-02-22"),   # 21-day tier
    V("CVE-2026-3333", "2026-02-01", "2026-02-11"),   # 10-day tier
    V("CVE-2012-1854", "2026-03-05", "2026-03-08", "Acme"),  # resurrected, Acme again
]


class TestGaps(unittest.TestCase):
    def test_deadline_gap(self):
        self.assertEqual(k.deadline_gap(FIXTURE[0]), 3)
        self.assertEqual(k.deadline_gap(FIXTURE[1]), 14)

    def test_median_gap(self):
        # gaps: 3, 14, 21, 10, 3 -> median 10
        self.assertEqual(k.median_gap(FIXTURE), 10)

    def test_median_empty(self):
        self.assertIsNone(k.median_gap([]))

    def test_tiers_sorted(self):
        self.assertEqual(k.deadline_tiers(FIXTURE), {3: 2, 10: 1, 14: 1, 21: 1})

    def test_by_year(self):
        self.assertEqual(k.by_year(FIXTURE), {2026: 5})


class TestResurrected(unittest.TestCase):
    def test_only_pre_2016(self):
        r = k.resurrected(FIXTURE)
        ids = [v["cveID"] for v in r]
        self.assertIn("CVE-2008-4250", ids)
        self.assertIn("CVE-2012-1854", ids)
        self.assertNotIn("CVE-2026-2222", ids)

    def test_newest_first(self):
        r = k.resurrected(FIXTURE)
        self.assertEqual(r[0]["cveID"], "CVE-2012-1854")  # added 2026-03-05

    def test_cve_age(self):
        self.assertEqual(k.cve_age_at_listing(FIXTURE[0]), 18)


class TestMisc(unittest.TestCase):
    def test_vendor_concentration(self):
        top = dict(k.vendor_concentration(FIXTURE))
        self.assertEqual(top["Acme"], 5)

    def test_added_since(self):
        r = k.added_since(FIXTURE, 30, today=date(2026, 3, 20))
        self.assertEqual([v["cveID"] for v in r], ["CVE-2012-1854"])

    def test_parse_date_tolerates_timestamp(self):
        self.assertEqual(k.parse_date("2026-01-10T12:00:00Z"), date(2026, 1, 10))


if __name__ == "__main__":
    unittest.main(verbosity=2)
