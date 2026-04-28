#!/usr/bin/env python3
"""
Phase2 archaeology: git blame on unprocessed candidates.
Updates candidates_ranked.json in place.
Stops after finding --target confirmed multi-commit candidates.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
RANKED = ROOT / "results" / "candidates_ranked.json"
DATASET = ROOT / "dataset"


def git_out(args, cwd, timeout=90):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else ""


def get_changed_py_files(repo_dir, fix_sha):
    out = git_out(["git", "diff-tree", "--no-commit-id", "-r", "--name-only", fix_sha], repo_dir)
    return [f for f in out.splitlines() if f.endswith(".py")]


def blame_file_at_parent(repo_dir, fix_sha, filepath):
    parent = fix_sha + "^"
    exists = git_out(["git", "ls-tree", "-r", "--name-only", parent], repo_dir)
    if filepath not in exists.splitlines():
        return []
    out = git_out(["git", "blame", "--porcelain", parent, "--", filepath], repo_dir, timeout=90)
    hashes = []
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]{40} ", line):
            hashes.append(line[:40])
    return [h for h in hashes if h != "0" * 40]


def run_archaeology(cand):
    cve_id = cand["cve_id"]
    owner, repo_name = cand["owner"], cand["repo_name"]
    fix_sha = cand["fix_commit"]
    clone_url = f"https://github.com/{owner}/{repo_name}.git"

    print(f"\n[{cve_id}] Cloning {owner}/{repo_name} ...", flush=True)
    tmpdir = tempfile.mkdtemp(prefix=f"ccvb_{cve_id}_")
    try:
        r = subprocess.run(
            ["git", "clone", "--depth=100", "--quiet", clone_url, tmpdir],
            capture_output=True, text=True, timeout=240,
        )
        if r.returncode != 0:
            print(f"  Clone failed: {r.stderr[:200]}")
            return {**cand, "phase2_done": True, "multi_commit_confirmed": False,
                    "distinct_blame_commits": 0, "phase2_error": "clone_failed"}

        subprocess.run(
            ["git", "fetch", "--depth=100", "origin", fix_sha],
            cwd=tmpdir, capture_output=True, timeout=90,
        )

        verify = git_out(["git", "cat-file", "-t", fix_sha], tmpdir)
        if verify != "commit":
            print(f"  Fix commit {fix_sha[:8]} not found")
            return {**cand, "phase2_done": True, "multi_commit_confirmed": False,
                    "distinct_blame_commits": 0, "phase2_error": "fix_commit_not_found"}

        py_files = get_changed_py_files(tmpdir, fix_sha)
        if not py_files:
            print(f"  No .py files changed")
            return {**cand, "phase2_done": True, "multi_commit_confirmed": False,
                    "distinct_blame_commits": 0, "phase2_error": "no_py_files"}

        print(f"  Fix touches {len(py_files)} py file(s): {py_files[:3]}", flush=True)

        all_blame: set[str] = set()
        file_results = []
        for fp in py_files[:5]:
            hashes = blame_file_at_parent(tmpdir, fix_sha, fp)
            unique = set(hashes)
            all_blame.update(unique)
            file_results.append({"filename": fp, "distinct_blame_commits": len(unique),
                                  "blame_commits": sorted(unique)})
            print(f"    blame {fp}: {len(unique)} distinct commits", flush=True)

        distinct = len(all_blame)
        confirmed = distinct >= 2
        print(f"  Total distinct: {distinct} -> {'CONFIRMED' if confirmed else 'single-commit'}")

        return {
            **cand,
            "phase2_done": True,
            "multi_commit_confirmed": confirmed,
            "distinct_blame_commits": distinct,
            "blame_commits": sorted(all_blame),
            "file_blame_results": file_results,
            "phase2_error": None,
        }

    except subprocess.TimeoutExpired:
        print(f"  Timeout!")
        return {**cand, "phase2_done": True, "multi_commit_confirmed": False,
                "distinct_blame_commits": 0, "phase2_error": "timeout"}
    except Exception as e:
        print(f"  Error: {e}")
        return {**cand, "phase2_done": True, "multi_commit_confirmed": False,
                "distinct_blame_commits": 0, "phase2_error": str(e)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, default=5, help="Stop after N confirmed")
    parser.add_argument("--max", type=int, default=20, help="Max candidates to process")
    args = parser.parse_args()

    data = json.loads(RANKED.read_text())
    candidates = data if isinstance(data, list) else data.get("candidates", [])

    dataset_cves = set(os.listdir(DATASET)) if DATASET.exists() else set()

    # Get unprocessed candidates not already in dataset
    pending = [c for c in candidates if not c.get("phase2_done") and c["cve_id"] not in dataset_cves]
    # Sort: critical first, then by phase1_score
    pending.sort(key=lambda x: (0 if x.get("severity") == "critical" else 1,
                                 -(x.get("phase1_score") or 0)))

    print(f"Pending phase2: {len(pending)} candidates")
    print(f"Target: {args.target} confirmed, max process: {args.max}")

    confirmed = []
    processed = 0
    idx_map = {c["cve_id"]: i for i, c in enumerate(candidates)}

    for cand in pending[:args.max]:
        result = run_archaeology(cand)
        # Update in-place
        idx = idx_map[cand["cve_id"]]
        candidates[idx] = result
        processed += 1

        if result["multi_commit_confirmed"]:
            confirmed.append(result)
            print(f"\n*** CONFIRMED #{len(confirmed)}: {cand['cve_id']} "
                  f"(distinct={result['distinct_blame_commits']}) ***")
        if len(confirmed) >= args.target:
            print(f"\nReached target of {args.target} confirmed. Stopping.")
            break

    # Save back
    out = data if isinstance(data, list) else {**data, "candidates": candidates}
    if isinstance(data, list):
        out = candidates
    RANKED.write_text(json.dumps(out, indent=2))
    print(f"\nSaved {RANKED}")
    print(f"\nSummary: processed={processed}, confirmed={len(confirmed)}")
    for c in confirmed:
        print(f"  {c['cve_id']}: distinct_blame={c['distinct_blame_commits']}, "
              f"repo={c['owner']}/{c['repo_name']}")


if __name__ == "__main__":
    main()
