#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — Metrics Aggregator (CVB-1d)

Reads all complete+sast annotation.json files and produces:
  - results/summary.json          aggregate CCDR / CDR / detection gap
  - results/per_cve_results.csv   per-CVE row with key fields

Usage:
  python scripts/compute_metrics.py
  python scripts/compute_metrics.py --include-complete   # include complete (no sast) with conservative MISSED
  python scripts/compute_metrics.py --print-table        # print ASCII result table
"""

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATASET = ROOT / "dataset"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def load_annotations(include_complete: bool = False) -> list[dict]:
    """Load annotation.json files. By default only complete+sast entries."""
    entries = []
    for ann_path in sorted(DATASET.glob("*/annotation.json")):
        d = json.loads(ann_path.read_text())
        status = d.get("annotation_status", "")
        if status == "complete+sast":
            entries.append(d)
        elif include_complete and status == "complete":
            # Treat as MISSED (conservative) — no SAST data
            d["_conservative_miss"] = True
            d.setdefault("ccdr_this_cve", False)
            d.setdefault("cdr_this_cve", False)
            entries.append(d)
    return entries


def compute_metrics(entries: list[dict]) -> dict:
    n = len(entries)
    if n == 0:
        return {"error": "no entries"}

    ccdr_hits = sum(1 for e in entries if e.get("ccdr_this_cve"))
    cdr_hits  = sum(1 for e in entries if e.get("cdr_this_cve"))

    ccdr = ccdr_hits / n
    cdr  = cdr_hits  / n
    gap  = cdr - ccdr

    # Breakdown by CWE category
    cwe_groups: dict[str, list] = {}
    for e in entries:
        for cwe in e.get("cwe_ids", ["unknown"]):
            cwe_groups.setdefault(cwe, []).append(e)

    cwe_stats = {}
    for cwe, group in sorted(cwe_groups.items()):
        ng = len(group)
        cwe_ccdr_hits = sum(1 for e in group if e.get("ccdr_this_cve"))
        cwe_cdr_hits  = sum(1 for e in group if e.get("cdr_this_cve"))
        cwe_stats[cwe] = {
            "n": ng,
            "CCDR": round(cwe_ccdr_hits / ng, 3),
            "CDR":  round(cwe_cdr_hits  / ng, 3),
        }

    # Span distribution
    spans = [e.get("commit_span_days", 0) for e in entries if e.get("commit_span_days")]
    span_min   = min(spans) if spans else 0
    span_max   = max(spans) if spans else 0
    span_mean  = round(sum(spans) / len(spans), 1) if spans else 0
    span_median = sorted(spans)[len(spans) // 2] if spans else 0

    # Severity distribution
    sev_counts: dict[str, int] = {}
    for e in entries:
        s = e.get("severity_combined", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "n_cves": n,
        "ccdr_hits": ccdr_hits,
        "cdr_hits":  cdr_hits,
        "CCDR": round(ccdr, 3),
        "CDR":  round(cdr, 3),
        "detection_gap": round(gap, 3),
        "CCDR_pct": f"{ccdr*100:.0f}%",
        "CDR_pct":  f"{cdr*100:.0f}%",
        "interpretation": (
            f"Per-commit SAST detected {ccdr_hits}/{n} CVEs ({ccdr*100:.0f}%). "
            f"Cumulative SAST detected {cdr_hits}/{n} CVEs ({cdr*100:.0f}%). "
            f"Detection gap = {gap*100:.0f}%."
        ),
        "commit_span_days": {
            "min": span_min, "max": span_max,
            "mean": span_mean, "median": span_median,
        },
        "severity_distribution": sev_counts,
        "by_cwe": cwe_stats,
    }


def build_per_cve_rows(entries: list[dict]) -> list[dict]:
    rows = []
    for e in entries:
        commits = e.get("contributing_commits", [])
        n_commits = len(commits)
        rows.append({
            "cve_id":          e.get("cve_id", ""),
            "repo":            e.get("repo", "").split("github.com/")[-1],
            "cwe_ids":         "|".join(e.get("cwe_ids", [])),
            "severity":        e.get("severity_combined", ""),
            "n_contributing":  n_commits,
            "commit_span_days": e.get("commit_span_days", ""),
            "ccdr_this_cve":   e.get("ccdr_this_cve", False),
            "cdr_this_cve":    e.get("cdr_this_cve", False),
            "per_commit_result": "CAUGHT" if e.get("ccdr_this_cve") else "missed",
            "cumulative_result": "CAUGHT" if e.get("cdr_this_cve") else "missed",
            "annotation_status": e.get("annotation_status", ""),
        })
    return rows


def print_table(entries: list[dict], metrics: dict):
    print(f"\n{'='*80}")
    print("CrossCommitVuln-Bench — Baseline SAST Results")
    print(f"{'='*80}")
    print(f"\n{'CVE':22} {'Sev':8} {'CWE':12} {'Span':6} {'Commits':8} {'Per-commit':12} {'Cumulative'}")
    print("-" * 80)
    for e in entries:
        cve  = e.get("cve_id", "")
        sev  = e.get("severity_combined", "")[:7]
        cwe  = "|".join(c.replace("CWE-", "") for c in e.get("cwe_ids", []))[:11]
        span = str(e.get("commit_span_days", "?"))
        nc   = str(len(e.get("contributing_commits", [])))
        pc   = "CAUGHT \u26a0" if e.get("ccdr_this_cve") else "missed \u2713"
        cu   = "CAUGHT \u26a0" if e.get("cdr_this_cve") else "missed \u2713"
        print(f"{cve:22} {sev:8} {cwe:12} {span:6} {nc:8} {pc:12} {cu}")

    print(f"\n{'─'*80}")
    print(f"  CVEs evaluated:       {metrics['n_cves']}")
    print(f"  CCDR (per-commit):    {metrics['CCDR_pct']}  ({metrics['ccdr_hits']}/{metrics['n_cves']} caught per-commit)")
    print(f"  CDR  (cumulative):    {metrics['CDR_pct']}  ({metrics['cdr_hits']}/{metrics['n_cves']} caught cumulatively)")
    print(f"  Detection gap:        {metrics['detection_gap']*100:.0f}%")
    print(f"\n  Commit span: {metrics['commit_span_days']['min']}d – {metrics['commit_span_days']['max']}d "
          f"(mean {metrics['commit_span_days']['mean']}d, median {metrics['commit_span_days']['median']}d)")
    print(f"\n  Severity: {metrics['severity_distribution']}")
    print(f"\n  By CWE:")
    for cwe, s in metrics["by_cwe"].items():
        print(f"    {cwe:10}  n={s['n']}  CCDR={s['CCDR']*100:.0f}%  CDR={s['CDR']*100:.0f}%")

    invisible_pct = round((1 - metrics['CCDR']) * 100)
    print(f"\n  Key result: {invisible_pct}% of chains are INVISIBLE to per-commit SAST.")
    print(f"  {metrics['interpretation']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-complete", action="store_true",
                        help="Include 'complete' (no SAST run) entries as conservative MISSED")
    parser.add_argument("--print-table", action="store_true",
                        help="Print ASCII results table to stdout")
    args = parser.parse_args()

    entries = load_annotations(include_complete=args.include_complete)
    if not entries:
        print("No complete+sast annotations found. Run run_baselines.py first.")
        sys.exit(1)

    print(f"Loaded {len(entries)} annotation(s) for metric computation.", file=sys.stderr)

    metrics = compute_metrics(entries)
    rows    = build_per_cve_rows(entries)

    # Save summary.json
    summary_path = RESULTS / "summary.json"
    summary_path.write_text(json.dumps({"metrics": metrics, "per_cve": rows}, indent=2))

    # Save per_cve_results.csv
    csv_path = RESULTS / "per_cve_results.csv"
    if rows:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    if args.print_table:
        print_table(entries, metrics)

    print(f"\nOutputs:")
    print(f"  {summary_path}")
    print(f"  {csv_path}")
    print(f"\nCCDR={metrics['CCDR_pct']}  CDR={metrics['CDR_pct']}  gap={metrics['detection_gap']*100:.0f}%  n={metrics['n_cves']}")


if __name__ == "__main__":
    main()
