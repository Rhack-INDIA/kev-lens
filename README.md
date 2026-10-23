# kev-lens

Compute real numbers from CISA's Known Exploited Vulnerabilities feed.

Everyone reads KEV as a list of CVEs. It is more useful as a dataset — especially the
gap between when a bug is **listed** and when it is **due**, because that gap is the
closest public signal of how much exploit capability already exists.

```
$ kev-lens stats

catalog 2026.10.21 · 1754 entries
median remediation window: 21.0 days
added by year: 2021:311, 2022:555, 2023:187, 2024:186, 2025:245, 2026:270
deadline tiers: 1d:6, 2d:4, 3d:142, 7d:20, 14d:280, 21d:1025, 43d:1, 181d:238
top vendors: Microsoft(390), Cisco(101), Apple(95), Adobe(82), Google(75)
```

That one line is the point: 142 entries now carry a **3-day** deadline while 1025 carry
the old 21-day one. A single "critical = patch in 30 days" policy is not describing
current practice.

## Install

```bash
git clone https://github.com/<you>/kev-lens && cd kev-lens
python3 kev_lens.py fetch          # caches the feed to ~/.cache/kev-lens/kev.json
```

No dependencies. Python 3.9+.

## Commands

| Command | What it shows |
|---|---|
| `kev-lens stats [--year YYYY]` | totals, median remediation window, additions by year, deadline tiers, top vendors |
| `kev-lens deadlines` | distribution of remediation windows as a bar histogram |
| `kev-lens resurrected` | entries whose CVE predates 2016 but were exploited far later |
| `kev-lens since 30` | what was added in the last N days, with due dates |
| `--json` on any command | machine-readable output |
| `--offline` | never hit the network, use the cache |

## Why `resurrected` exists

Some KEV additions are not new bugs at all — they are 10–18 year old CVEs that finally
got exploited. `kev-lens resurrected` surfaces them, which is useful when you are
arguing that "we don't run anything that old" is a testable claim rather than a fact.

```
$ kev-lens resurrected
23 entries whose CVE predates 2016 but were exploited later (newest first):
  2026-10-16  CVE-2008-4250       Microsoft          Windows
```

## Design notes

- **No network in the compute path.** `fetch` writes a JSON cache; every other command
  reads it. That makes runs reproducible and safe in CI.
- **Pure functions.** Gap, tier, age and vendor logic are plain functions over dicts,
  so they are unit tested against a fixture rather than the live feed (the feed changes
  daily, your tests should not).
- **Median, not mean.** One 181-day outlier should not move the headline number.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 11 tests
```

## Licence

MIT. KEV data is published by CISA (US Government work).
