#!/usr/bin/env python3
"""kev-lens — compute real numbers from CISA's Known Exploited Vulnerabilities feed.

Most people read KEV as a list. It is more useful as a dataset: the gap between
`dateAdded` and `dueDate` has been collapsing, and that gap is the closest public
signal of how fast exploit code actually exists.

Usage:
    kev-lens fetch                    # download + cache the feed
    kev-lens stats                    # headline numbers
    kev-lens stats --year 2026        # one year
    kev-lens deadlines                # deadline-tier distribution
    kev-lens resurrected              # old CVEs that came back
    kev-lens since 30                 # additions in the last N days
    (--json on any command)
"""
from __future__ import annotations
import argparse, json, os, re, statistics, sys, urllib.request
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = Path(os.environ.get("KEV_LENS_CACHE", Path.home() / ".cache" / "kev-lens" / "kev.json"))


# ---------- loading ----------
def fetch(force: bool = False) -> dict:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    if CACHE.exists() and not force:
        return json.loads(CACHE.read_text())
    req = urllib.request.Request(FEED, headers={"User-Agent": "kev-lens/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode())
    CACHE.write_text(json.dumps(data))
    return data


def vulns(data: dict) -> list[dict]:
    return data.get("vulnerabilities", [])


# ---------- pure computations (unit-testable) ----------
def parse_date(s: str) -> date:
    return datetime.strptime(s[:10], "%Y-%m-%d").date()


def deadline_gap(v: dict) -> int:
    """Days between being listed and being due — the remediation window."""
    return (parse_date(v["dueDate"]) - parse_date(v["dateAdded"])).days


def by_year(vs: list[dict], field: str = "dateAdded") -> dict[int, int]:
    return dict(sorted(Counter(parse_date(v[field]).year for v in vs).items()))


def deadline_tiers(vs: list[dict]) -> dict[int, int]:
    return dict(sorted(Counter(deadline_gap(v) for v in vs).items()))


def median_gap(vs: list[dict]) -> float | None:
    return statistics.median(deadline_gap(v) for v in vs) if vs else None


def cve_age_at_listing(v: dict) -> int | None:
    """Years between CVE publication year and KEV listing — finds 'resurrected' bugs."""
    m = re.match(r"CVE-(\d{4})-", v.get("cveID", ""))
    return parse_date(v["dateAdded"]).year - int(m.group(1)) if m else None


def resurrected(vs: list[dict], before_year: int = 2016) -> list[dict]:
    out = [v for v in vs if (cve_age_at_listing(v) or 0) >= 1
           and int(re.match(r"CVE-(\d{4})-", v["cveID"]).group(1)) < before_year]
    return sorted(out, key=lambda v: v["dateAdded"], reverse=True)


def vendor_concentration(vs: list[dict], top: int = 5) -> list[tuple[str, int]]:
    return Counter(v.get("vendorProject", "?") for v in vs).most_common(top)


def added_since(vs: list[dict], days: int, today: date | None = None) -> list[dict]:
    cutoff = (today or date.today()) - timedelta(days=days)
    return sorted([v for v in vs if parse_date(v["dateAdded"]) >= cutoff],
                  key=lambda v: v["dateAdded"], reverse=True)


# ---------- cli ----------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kev-lens", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--offline", action="store_true", help="use cache only, never fetch")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fetch"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("stats"); p.add_argument("--year", type=int)
    sub.add_parser("deadlines")
    sub.add_parser("resurrected")
    p = sub.add_parser("since"); p.add_argument("days", type=int)

    a = ap.parse_args(argv)
    if a.cmd == "fetch":
        d = fetch(force=a.force)
        print(f"cached {len(vulns(d))} entries -> {CACHE}")
        return 0

    try:
        data = fetch(force=False) if not a.offline else json.loads(CACHE.read_text())
    except FileNotFoundError:
        print("no cache; run `kev-lens fetch` first", file=sys.stderr); return 2

    vs = vulns(data)
    if a.cmd == "stats":
        sel = [v for v in vs if parse_date(v["dateAdded"]).year == a.year] if a.year else vs
        out = {
            "catalog_version": data.get("catalogVersion"),
            "total": len(vs),
            "selected": len(sel),
            "median_deadline_days": median_gap(sel),
            "added_by_year": by_year(sel),
            "deadline_tiers": deadline_tiers(sel),
            "top_vendors": vendor_concentration(sel),
        }
        if a.json:
            print(json.dumps(out, indent=2, default=str)); return 0
        print(f"catalog {out['catalog_version']} · {out['total']} entries"
              + (f" · {out['selected']} in {a.year}" if a.year else ""))
        print(f"median remediation window: {out['median_deadline_days']} days")
        print("added by year: " + ", ".join(f"{y}:{n}" for y, n in out["added_by_year"].items()))
        print("deadline tiers: " + ", ".join(f"{d}d:{n}" for d, n in out["deadline_tiers"].items()))
        print("top vendors: " + ", ".join(f"{v}({n})" for v, n in out["top_vendors"]))
    elif a.cmd == "deadlines":
        t = deadline_tiers(vs)
        if a.json: print(json.dumps(t, indent=2)); return 0
        print("remediation window distribution (days -> count):")
        for d, n in t.items():
            print(f"  {d:>3}d  {n:>5}  {'#' * min(60, n // 10)}")
    elif a.cmd == "resurrected":
        r = resurrected(vs)
        if a.json: print(json.dumps(r, indent=2)); return 0
        print(f"{len(r)} entries whose CVE predates 2016 but were exploited later (newest first):")
        for v in r[:15]:
            print(f"  {v['dateAdded']}  {v['cveID']:<18} {v['vendorProject'][:18]:<18} {v['product'][:20]}")
    elif a.cmd == "since":
        r = added_since(vs, a.days)
        if a.json: print(json.dumps(r, indent=2)); return 0
        print(f"{len(r)} additions in the last {a.days} days:")
        for v in r[:25]:
            print(f"  {v['dateAdded']} due {v['dueDate']}  {v['cveID']:<18} {v['vendorProject'][:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
