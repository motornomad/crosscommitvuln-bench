#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — CVE Mining Script

Phase 1 (API-only, ~10 min, ~50 req):
  Query GitHub Advisory Database for high/critical PyPI CVEs.
  Filter for advisories whose references contain GitHub fix-commit URLs.
  Fetch changed-file metadata for each fix commit via GitHub Commits API.
  Filter: fix modifies >=2 Python files (proxy for multi-commit introduction).
  Output: results/candidates_raw.json

Phase 2 (git blame, ~30-60 min):
  For top N candidates from Phase 1.
  Shallow-clone repo, checkout state just before fix commit.
  Run git blame on the lines the fix commit touched.
  Score: number of distinct commits that INTRODUCED the vulnerable lines.
  >= 2 distinct introducing commits = strong multi-commit candidate.
  Output: results/candidates_ranked.json
  All clones cleaned up immediately (disk-safe).

Usage:
  python scripts/mine_candidates.py --phase 1
  python scripts/mine_candidates.py --phase 2 --top 30
  python scripts/mine_candidates.py --phase all

Environment:
  GITHUB_TOKEN   — optional but strongly recommended (60 req/hr without, 5000/hr with)
                   Create at github.com/settings/tokens (no permissions needed for public repos)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
DATASET = ROOT / "dataset"
RESULTS.mkdir(exist_ok=True)
DATASET.mkdir(exist_ok=True)

RAW_OUTPUT = RESULTS / "candidates_raw.json"
RANKED_OUTPUT = RESULTS / "candidates_ranked.json"

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("POSTURA_GITHUB_PAT")
GH_API = "https://api.github.com"
GHSA_ADVISORIES = f"{GH_API}/advisories"

HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    print(f"GitHub token loaded — rate limit: 5000 req/hr")
else:
    print("WARNING: No GITHUB_TOKEN set — rate limit: 60 req/hr.")
    print("  Set GITHUB_TOKEN to a classic PAT (no special permissions needed).")
    print("  Proceeding with conservative request pacing.\n")

# ── GitHub API helpers ────────────────────────────────────────────────────────

def _gh_get(url: str, params: dict = None, retry: int = 3) -> Optional[dict | list]:
    """GET with rate-limit backoff and retry."""
    for attempt in range(retry):
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
        except requests.RequestException as e:
            print(f"    Request error ({e}), retrying...", flush=True)
            time.sleep(5)
            continue

        remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
        if remaining < 5:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 65))
            wait = max(reset_ts - time.time(), 5) + 2
            print(f"    Rate limit low ({remaining} remaining). Waiting {wait:.0f}s...", flush=True)
            time.sleep(wait)

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 403:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 65))
            wait = max(reset_ts - time.time(), 5) + 2
            print(f"    Rate limited (403). Waiting {wait:.0f}s...", flush=True)
            time.sleep(wait)
        elif resp.status_code == 404:
            return None
        elif resp.status_code == 422:
            return None  # unprocessable — bad commit ref, skip
        else:
            print(f"    HTTP {resp.status_code} for {url}", flush=True)
            time.sleep(3)
    return None


# ── Fix commit extraction ─────────────────────────────────────────────────────

_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/\s\"']+)/commit/([0-9a-f]{7,40})")
_PR_RE = re.compile(r"github\.com/([^/]+)/([^/\s\"']+)/pull/(\d+)")


def extract_fix_commits(references: list) -> list[dict]:
    """
    Parse advisory references for GitHub commit URLs.
    Returns list of {owner, repo, sha, url}.
    """
    seen = set()
    commits = []
    for ref in references:
        url = ref if isinstance(ref, str) else ref.get("url", "")
        m = _COMMIT_RE.search(url)
        if m:
            owner, repo, sha = m.groups()
            repo = repo.rstrip("/")
            key = f"{owner}/{repo}@{sha[:7]}"
            if key not in seen:
                seen.add(key)
                commits.append({"owner": owner, "repo": repo, "sha": sha, "url": url})
    return commits


# ── Patch line range parser ───────────────────────────────────────────────────

def _parse_patch_old_line_ranges(patch: str) -> list[tuple[int, int]]:
    """
    Parse unified diff patch to get old-file line ranges of deleted/modified lines.
    These are the vulnerable lines we'll blame.
    Returns list of (start, end) inclusive line number tuples.
    """
    if not patch:
        return []
    ranges = []
    old_line = 0
    for line in patch.splitlines():
        m = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", line)
        if m:
            old_line = int(m.group(1))
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            # This line exists in the old file (vulnerable)
            ranges.append(old_line)
            old_line += 1
        elif not line.startswith("+"):
            old_line += 1
        # "+" lines don't exist in old file, don't advance old_line

    if not ranges:
        return []

    # Merge contiguous line numbers into ranges
    merged = []
    start = end = ranges[0]
    for n in ranges[1:]:
        if n <= end + 3:  # merge if within 3 lines (common in real patches)
            end = n
        else:
            merged.append((start, end))
            start = end = n
    merged.append((start, end))
    return merged


# ── Phase 1: API mining ───────────────────────────────────────────────────────

def phase1_mine(max_pages: int = 6) -> list[dict]:
    """
    Fetch PyPI high/critical advisories from GitHub Advisory Database.
    For those with GitHub fix-commit URLs in references, fetch commit file metadata.
    Filter to candidates where the fix touches >=2 Python files.
    Output: results/candidates_raw.json
    """
    print("=" * 60)
    print("PHASE 1: API Mining")
    print("=" * 60)

    # Step A: collect advisories (no per-advisory API calls yet)
    print("\n[A] Fetching advisories from GHSA...")
    advisories = []
    for severity in ("critical", "high"):
        page = 1
        while page <= max_pages:
            print(f"  {severity} page {page}...", flush=True)
            data = _gh_get(GHSA_ADVISORIES, params={
                "ecosystem": "pip",
                "severity": severity,
                "per_page": 100,
                "page": page,
            })
            if not data or not isinstance(data, list):
                break
            advisories.extend(data)
            print(f"    Got {len(data)} advisories (total so far: {len(advisories)})", flush=True)
            if len(data) < 100:
                break
            page += 1
            time.sleep(1.5 if not GITHUB_TOKEN else 0.3)

    print(f"\nTotal advisories fetched: {len(advisories)}")

    # Step B: local filtering — keep only those with GitHub fix-commit URLs in references
    print("\n[B] Filtering for GitHub fix-commit URLs in references (no API calls)...")
    with_commits = []
    for adv in advisories:
        cve_id = adv.get("cve_id")
        if not cve_id:
            continue
        refs = adv.get("references", [])
        ref_urls = [r if isinstance(r, str) else r.get("url", "") for r in refs]
        fix_commits = extract_fix_commits(ref_urls)
        if not fix_commits:
            continue
        with_commits.append((adv, fix_commits))

    print(f"Advisories with traceable fix commits: {len(with_commits)}")

    # Step C: for each candidate, fetch commit file metadata
    print(f"\n[C] Fetching commit file metadata ({len(with_commits)} candidates)...")
    print("    (1 API call per candidate — budget conscious)")
    candidates = []

    for adv, fix_commits in with_commits:
        cve_id = adv.get("cve_id")
        severity = adv.get("severity", "unknown")
        ghsa_id = adv.get("ghsa_id", "")
        summary = adv.get("summary", "")
        cwes = [c.get("cwe_id") for c in adv.get("cwes", []) if c.get("cwe_id")]

        # Try up to 2 fix commits per advisory
        for fc in fix_commits[:2]:
            owner, repo_name, sha = fc["owner"], fc["repo"], fc["sha"]
            commit_url = f"{GH_API}/repos/{owner}/{repo_name}/commits/{sha}"
            data = _gh_get(commit_url)
            if not data:
                continue

            files = data.get("files", [])
            py_files = []
            for f in files:
                fname = f.get("filename", "")
                if not fname.endswith(".py"):
                    continue
                patch = f.get("patch", "")
                old_line_ranges = _parse_patch_old_line_ranges(patch)
                py_files.append({
                    "filename": fname,
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "old_line_ranges": old_line_ranges,
                    "patch_preview": patch[:300] if patch else "",
                })

            if len(py_files) < 2:
                # Single-file fix is less likely to be multi-commit — skip
                continue

            total_del = sum(f["deletions"] for f in py_files)
            total_add = sum(f["additions"] for f in py_files)
            # Heuristic score: more files + more deletions (removed vulnerable code) = better
            phase1_score = len(py_files) * 3 + min(total_del, 20) + min(total_add // 2, 5)

            candidate = {
                "cve_id": cve_id,
                "ghsa_id": ghsa_id,
                "severity": severity,
                "cwe_ids": cwes,
                "summary": summary,
                "repo": f"https://github.com/{owner}/{repo_name}",
                "owner": owner,
                "repo_name": repo_name,
                "fix_commit": sha,
                "fix_commit_url": fc["url"],
                "py_files_changed": len(py_files),
                "total_deletions": total_del,
                "total_additions": total_add,
                "phase1_score": phase1_score,
                "files": py_files,
                # Phase 2 fields (filled in later)
                "phase2_done": False,
                "distinct_blame_commits": None,
                "blame_commits": [],
                "file_blame_results": [],
                "multi_commit_confirmed": False,
                "phase2_error": None,
            }
            candidates.append(candidate)
            print(
                f"  ✓ {cve_id} ({severity}) — {len(py_files)} py files, "
                f"{total_del} deletions, score={phase1_score}",
                flush=True,
            )
            time.sleep(0.5 if not GITHUB_TOKEN else 0.1)
            break  # one fix commit per advisory is enough for Phase 1

    candidates.sort(key=lambda x: -x["phase1_score"])

    print(f"\nPhase 1 complete: {len(candidates)} candidates")
    RAW_OUTPUT.write_text(json.dumps(candidates, indent=2))
    print(f"Saved → {RAW_OUTPUT}\n")

    # Summary table
    print(f"{'CVE':20} {'Severity':10} {'Files':6} {'Del':5} {'Score':6}  Summary")
    print("-" * 80)
    for c in candidates[:20]:
        summary_short = c["summary"][:40] if c["summary"] else ""
        print(
            f"{c['cve_id']:20} {c['severity']:10} {c['py_files_changed']:6} "
            f"{c['total_deletions']:5} {c['phase1_score']:6}  {summary_short}"
        )
    if len(candidates) > 20:
        print(f"  ... and {len(candidates) - 20} more in {RAW_OUTPUT}")

    return candidates


# ── Phase 2: Git blame analysis ───────────────────────────────────────────────

def phase2_blame(candidates: list[dict], top_n: int = 30) -> list[dict]:
    """
    For top N candidates: shallow-clone, git blame pre-fix state, count distinct
    commits that introduced the vulnerable lines.
    >= 2 distinct introducing commits = multi_commit_confirmed = True.
    Clones are deleted immediately after each analysis (disk-safe).
    """
    print("=" * 60)
    print(f"PHASE 2: Git Blame Analysis (top {top_n})")
    print("=" * 60)

    todo = [c for c in candidates if not c.get("phase2_done")][:top_n]
    print(f"\nAnalyzing {len(todo)} candidates...\n")

    for i, c in enumerate(todo):
        cve_id = c["cve_id"]
        owner = c["owner"]
        repo_name = c["repo_name"]
        fix_sha = c["fix_commit"]
        print(f"[{i+1}/{len(todo)}] {cve_id} — {owner}/{repo_name}", flush=True)

        tmpdir = tempfile.mkdtemp(prefix="ccvb_")
        try:
            # Shallow clone into /tmp (separate from home disk ideally)
            clone_url = f"https://github.com/{owner}/{repo_name}.git"
            print(f"  Cloning (depth=100)...", flush=True)
            r = subprocess.run(
                ["git", "clone", "--depth=100", "--quiet", clone_url, tmpdir],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode != 0:
                print(f"  ✗ Clone failed: {r.stderr.strip()[:150]}", flush=True)
                c["phase2_done"] = True
                c["phase2_error"] = f"clone_failed: {r.stderr.strip()[:100]}"
                continue

            # Fetch the fix commit specifically (may not be in default shallow clone)
            subprocess.run(
                ["git", "fetch", "--depth=100", "origin", fix_sha],
                cwd=tmpdir, capture_output=True, timeout=60,
            )

            # Get the parent of the fix commit (= vulnerable state)
            pre_fix = _git_parent(tmpdir, fix_sha)
            if not pre_fix:
                print(f"  ✗ fix commit {fix_sha[:8]} not in shallow clone", flush=True)
                c["phase2_done"] = True
                c["phase2_error"] = "commit_not_reachable"
                continue

            print(f"  fix={fix_sha[:8]}  pre-fix={pre_fix[:8]}", flush=True)

            # Git blame each changed Python file at the pre-fix state
            all_blame_commits: set[str] = set()
            file_results = []

            for f in c["files"]:
                fname = f["filename"]
                line_ranges = f["old_line_ranges"]
                if not line_ranges:
                    # No specific lines parsed from patch — blame whole file (less precise)
                    blame_commits = _blame_whole_file(tmpdir, pre_fix, fname)
                else:
                    blame_commits = _blame_line_ranges(tmpdir, pre_fix, fname, line_ranges)

                # Strip the boundary commit(s) — oldest commit in shallow clone
                # (boundary commits are NOT the true introducers, just the depth limit)
                blame_commits = _strip_boundary_commits(tmpdir, blame_commits)

                all_blame_commits.update(blame_commits)
                file_results.append({
                    "filename": fname,
                    "distinct_blame_commits": len(blame_commits),
                    "blame_commits": list(blame_commits),
                })
                print(
                    f"    {fname}: {len(blame_commits)} distinct introducing commits",
                    flush=True,
                )

            c["phase2_done"] = True
            c["distinct_blame_commits"] = len(all_blame_commits)
            c["blame_commits"] = list(all_blame_commits)
            c["file_blame_results"] = file_results
            c["multi_commit_confirmed"] = len(all_blame_commits) >= 2

            symbol = "✓ MULTI-COMMIT" if c["multi_commit_confirmed"] else "✗ single-commit"
            print(
                f"  {symbol}: {len(all_blame_commits)} distinct introducing commit(s)\n",
                flush=True,
            )

        except subprocess.TimeoutExpired:
            print(f"  ✗ Timeout\n", flush=True)
            c["phase2_done"] = True
            c["phase2_error"] = "timeout"
        except Exception as e:
            print(f"  ✗ Error: {e}\n", flush=True)
            c["phase2_done"] = True
            c["phase2_error"] = str(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)  # always clean up

    # Sort: confirmed multi-commit first, then by distinct_blame_commits desc
    candidates.sort(key=lambda x: (
        0 if x.get("multi_commit_confirmed") else 1,
        -(x.get("distinct_blame_commits") or 0),
        -x.get("phase1_score", 0),
    ))

    confirmed = [c for c in candidates if c.get("multi_commit_confirmed")]
    print(f"\nPhase 2 complete: {len(confirmed)}/{len(todo)} confirmed multi-commit")
    RANKED_OUTPUT.write_text(json.dumps(candidates, indent=2))
    print(f"Saved → {RANKED_OUTPUT}\n")

    if confirmed:
        print("=" * 60)
        print("TOP MULTI-COMMIT CANDIDATES (proceed to manual annotation)")
        print("=" * 60)
        for c in confirmed[:10]:
            print(f"\n  {c['cve_id']} ({c['severity']})")
            print(f"  {c['repo']}/commit/{c['fix_commit']}")
            print(f"  CWEs: {c['cwe_ids']}")
            print(f"  Distinct introducing commits: {c['distinct_blame_commits']}")
            print(f"  Summary: {c['summary'][:80]}")
    else:
        print("No multi-commit candidates found in this batch.")
        print("Try increasing --top or running phase 1 with --max-pages higher.")

    return candidates


# ── Git helpers ───────────────────────────────────────────────────────────────

def _git(args: list[str], cwd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _git_parent(repo_dir: str, sha: str) -> Optional[str]:
    """Return the first parent commit of sha."""
    r = _git(["git", "rev-parse", f"{sha}^"], repo_dir)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    # fallback: log
    r2 = _git(["git", "log", "--pretty=%P", "-1", sha], repo_dir)
    if r2.returncode == 0 and r2.stdout.strip():
        parents = r2.stdout.strip().split()
        return parents[0] if parents else None
    return None


def _blame_line_ranges(
    repo_dir: str, commit: str, filename: str, ranges: list[tuple[int, int]]
) -> set[str]:
    """
    git blame --porcelain on specific line ranges of filename at commit.
    Returns set of introducing commit hashes.
    """
    commits = set()
    for start, end in ranges:
        if start <= 0 or end < start:
            continue
        r = _git(
            ["git", "blame", "-L", f"{start},{end}", "--porcelain", commit, "--", filename],
            repo_dir, timeout=30,
        )
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            if re.match(r"^[0-9a-f]{40} \d+ \d+", line):
                commits.add(line.split()[0])
    return commits


def _blame_whole_file(repo_dir: str, commit: str, filename: str) -> set[str]:
    """Blame entire file — used when patch parsing yields no line ranges."""
    r = _git(
        ["git", "blame", "--porcelain", commit, "--", filename],
        repo_dir, timeout=60,
    )
    if r.returncode != 0:
        return set()
    commits = set()
    for line in r.stdout.splitlines():
        if re.match(r"^[0-9a-f]{40} \d+ \d+", line):
            commits.add(line.split()[0])
    return commits


def _strip_boundary_commits(repo_dir: str, commits: set[str]) -> set[str]:
    """
    Remove commits that are at the boundary of the shallow clone
    (not the true first commit — just the depth limit).
    These would inflate distinct_blame_commits spuriously.
    """
    boundary = set()
    r = _git(["git", "log", "--pretty=%H", "--boundary", "--all"], repo_dir, timeout=10)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if line.startswith("-"):
                boundary.add(line[1:])
    return commits - boundary


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CrossCommitVuln-Bench CVE miner")
    parser.add_argument(
        "--phase", choices=["1", "2", "all"], default="all",
        help="Which phase to run (default: all)",
    )
    parser.add_argument(
        "--top", type=int, default=30,
        help="Top N candidates for Phase 2 git blame (default: 30)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=6,
        help="Max GHSA pages per severity level (100 advisories/page, default: 6)",
    )
    args = parser.parse_args()

    if args.phase in ("1", "all"):
        candidates = phase1_mine(max_pages=args.max_pages)
    else:
        if not RAW_OUTPUT.exists():
            print(f"Error: {RAW_OUTPUT} not found. Run --phase 1 first.")
            sys.exit(1)
        candidates = json.loads(RAW_OUTPUT.read_text())
        print(f"Loaded {len(candidates)} candidates from Phase 1.")

    if args.phase in ("2", "all"):
        phase2_blame(candidates, top_n=args.top)

    print("\nAll done.")


if __name__ == "__main__":
    main()
