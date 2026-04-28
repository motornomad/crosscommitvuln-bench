#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — Git Archaeology Script (CVB-S4)

For each target CVE:
1. Clone repo (shallow depth=200)
2. Read the fix commit diff to understand WHAT was fixed
3. For each blame commit that introduced the vulnerable lines:
   - Get: hash, date, author, commit message, files it touched
   - Get: the specific diff of that commit for the relevant file
4. Identify the 2-3 KEY introducing commits that tell the clearest story
5. Output:
   - results/archaeology/<CVE_ID>/blame_commit_details.json
   - results/archaeology/<CVE_ID>/fix_commit_diff.txt
   - results/archaeology/<CVE_ID>/annotation_skeleton.json
   - dataset/<CVE_ID>/annotation.json  (pre-filled, needs human review)
   - dataset/<CVE_ID>/reproduction.md  (step-by-step)

Usage:
  python scripts/archaeology.py --cves CVE-2025-10283 CVE-2026-32247 CVE-2026-33154 CVE-2026-27602 CVE-2026-28490
  python scripts/archaeology.py --top 5   # auto-pick top 5 by distinct_blame_commits (excluding outliers)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
DATASET = ROOT / "dataset"
ARCH_DIR = RESULTS / "archaeology"
ARCH_DIR.mkdir(exist_ok=True)

RANKED = RESULTS / "candidates_ranked.json"

# ── git helpers ───────────────────────────────────────────────────────────────

def git(args: list[str], cwd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def git_out(args: list[str], cwd: str, timeout: int = 60) -> str:
    r = git(args, cwd, timeout)
    return r.stdout.strip() if r.returncode == 0 else ""


# ── commit detail fetcher ─────────────────────────────────────────────────────

def get_commit_detail(repo_dir: str, sha: str) -> dict:
    """Return structured info about a single commit."""
    # format: hash|author|date_iso|subject
    fmt = git_out(
        ["git", "log", "-1", "--pretty=%H|%an|%aI|%s", sha], repo_dir
    )
    if not fmt:
        return {"sha": sha, "error": "not_found"}
    parts = fmt.split("|", 3)
    if len(parts) < 4:
        return {"sha": sha, "error": "parse_failed"}
    full_sha, author, date_iso, subject = parts

    # full commit message body
    body = git_out(["git", "log", "-1", "--pretty=%b", sha], repo_dir)

    # files changed
    files_changed = git_out(
        ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha], repo_dir
    ).splitlines()

    return {
        "sha": full_sha,
        "short_sha": full_sha[:8],
        "author": author,
        "date": date_iso,
        "subject": subject,
        "body": body[:500] if body else "",
        "files_changed": files_changed,
    }


def get_file_diff_at_commit(repo_dir: str, sha: str, filename: str) -> str:
    """Get the diff introduced by sha for a specific file."""
    diff = git_out(
        ["git", "show", "--unified=5", sha, "--", filename], repo_dir, timeout=30
    )
    # Truncate very long diffs
    lines = diff.splitlines()
    if len(lines) > 120:
        lines = lines[:120] + [f"... [{len(lines)-120} more lines truncated]"]
    return "\n".join(lines)


def get_fix_commit_diff(repo_dir: str, fix_sha: str) -> str:
    """Get full diff of the fix commit."""
    diff = git_out(
        ["git", "show", "--unified=8", fix_sha], repo_dir, timeout=60
    )
    lines = diff.splitlines()
    if len(lines) > 300:
        lines = lines[:300] + [f"... [{len(lines)-300} more lines truncated]"]
    return "\n".join(lines)


# ── blame commit clustering ───────────────────────────────────────────────────

def identify_key_commits(
    repo_dir: str,
    blame_commits: list[str],
    files: list[dict],
    fix_sha: str,
) -> list[dict]:
    """
    From all blame commits, identify the 2-5 KEY ones:
    - Fetch commit details for all
    - Sort by date
    - Pick those that touch functionally distinct files (source vs sink)
    - Return sorted chronologically (commit A first, commit B last)
    """
    commit_details = []
    seen = set()
    for sha in blame_commits:
        if sha in seen:
            continue
        seen.add(sha)
        detail = get_commit_detail(repo_dir, sha)
        if "error" not in detail:
            commit_details.append(detail)

    if not commit_details:
        return []

    # Sort by date ascending
    commit_details.sort(key=lambda x: x.get("date", ""))

    # Filter out the fix commit itself if it sneaked in
    commit_details = [c for c in commit_details if not fix_sha.startswith(c["sha"][:8])]

    # Cluster by functional area: group commits by which files they touch
    # Key heuristic: commits touching different files = more interesting (multi-area)
    file_to_commits: dict[str, list[str]] = {}
    for detail in commit_details:
        for f in detail["files_changed"]:
            file_to_commits.setdefault(f, []).append(detail["sha"])

    # Score: commits that touch files not touched by any other commit are "unique" introducers
    unique_commits = set()
    for f, shas in file_to_commits.items():
        if len(shas) == 1:
            unique_commits.add(shas[0])

    # Pick: all unique commits + the earliest + the latest (max 6 total)
    key_shas = set()
    key_shas.update(list(unique_commits)[:4])
    if commit_details:
        key_shas.add(commit_details[0]["sha"])   # earliest
        key_shas.add(commit_details[-1]["sha"])  # latest (closest to fix)

    key_commits = [c for c in commit_details if c["sha"] in key_shas]
    key_commits.sort(key=lambda x: x.get("date", ""))
    return key_commits[:6]


# ── annotation skeleton builder ──────────────────────────────────────────────

def build_annotation(candidate: dict, key_commits: list[dict], repo_dir: str) -> dict:
    """Build a pre-filled annotation.json skeleton."""
    # Estimate isolated severity: if commit message mentions security words, bump to medium
    # otherwise low — human will review
    def estimate_isolated_severity(subject: str) -> str:
        sec_words = re.compile(
            r"security|auth|sanitiz|escap|inject|bypass|traversal|vuln|cve|fix.*bug|patch",
            re.I,
        )
        if sec_words.search(subject):
            return "medium"
        return "low"

    contributing_commits = []
    for c in key_commits:
        contributing_commits.append({
            "hash": c["sha"],
            "short_hash": c["short_sha"],
            "date": c["date"][:10] if c["date"] else "",
            "author": c["author"],
            "subject": c["subject"],
            "files_changed": c["files_changed"],
            "isolated_severity": estimate_isolated_severity(c["subject"]),
            "isolated_severity_note": "TODO: verify by running semgrep/bandit on this commit",
            "semgrep_findings": [],
            "bandit_findings": [],
        })

    return {
        "cve_id": candidate["cve_id"],
        "ghsa_id": candidate["ghsa_id"],
        "repo": candidate["repo"],
        "ecosystem": "PyPI",
        "cwe_ids": candidate["cwe_ids"],
        "severity_combined": candidate["severity"],
        "summary": candidate["summary"],
        "fix_commit": candidate["fix_commit"],
        "fix_commit_url": candidate["fix_commit_url"],
        "contributing_commits": contributing_commits,
        "vulnerability_chain": {
            "description": "TODO: describe the chain — which commit introduced the source, which introduced the sink, and why their combination is exploitable",
            "attack_vector": "network",
            "exploitability": "TODO: high/medium/low",
            "why_sast_misses_per_commit": "TODO: explain why each commit individually looks benign to SAST",
        },
        "annotation_status": "skeleton — needs human review",
        "distinct_blame_commits_total": candidate["distinct_blame_commits"],
        "key_commits_identified": len(contributing_commits),
    }


# ── main archaeology function ─────────────────────────────────────────────────

def deep_log_trace(repo_dir: str, files: list[dict], fix_sha: str, max_commits: int = 30) -> list[str]:
    """
    When phase2 blame gives ≤1 commit, do a deeper git log trace:
    walk the log history of each fix file before the fix commit and
    return distinct shas (excluding the fix commit itself).
    """
    all_shas: list[str] = []
    seen: set[str] = set()
    for f in files:
        fname = f.get("filename", "")
        if not fname.endswith(".py"):
            continue
        r = subprocess.run(
            ["git", "log", "--follow", "--format=%H", f"{fix_sha}^", "--", fname],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
        )
        for sha in r.stdout.strip().splitlines():
            sha = sha.strip()
            if sha and sha not in seen and not fix_sha.startswith(sha[:8]):
                seen.add(sha)
                all_shas.append(sha)
            if len(all_shas) >= max_commits:
                break
        if len(all_shas) >= max_commits:
            break
    return all_shas[:max_commits]


def analyse_cve(candidate: dict) -> bool:
    cve_id = candidate["cve_id"]
    owner = candidate["owner"]
    repo_name = candidate["repo_name"]
    fix_sha = candidate["fix_commit"]
    blame_commits = candidate.get("blame_commits", [])

    print(f"\n{'='*60}")
    print(f"Archaelogy: {cve_id}")
    print(f"Repo: {owner}/{repo_name}   Fix: {fix_sha[:8]}")
    print(f"Blame commits from Phase 2: {len(blame_commits)}")
    print(f"{'='*60}")

    out_dir = ARCH_DIR / cve_id
    out_dir.mkdir(exist_ok=True)
    dataset_dir = DATASET / cve_id
    dataset_dir.mkdir(exist_ok=True)

    tmpdir = tempfile.mkdtemp(prefix=f"ccvb_{cve_id}_")
    try:
        # Clone
        clone_url = f"https://github.com/{owner}/{repo_name}.git"
        print(f"Cloning (depth=200)...", flush=True)
        r = subprocess.run(
            ["git", "clone", "--depth=200", "--quiet", clone_url, tmpdir],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            print(f"Clone failed: {r.stderr[:200]}")
            return False

        # Fetch fix commit + deepen history if needed
        subprocess.run(
            ["git", "fetch", "--depth=500", "origin", fix_sha],
            cwd=tmpdir, capture_output=True, timeout=60,
        )
        subprocess.run(
            ["git", "fetch", "--deepen=300"],
            cwd=tmpdir, capture_output=True, timeout=60,
        )

        # 1. Fix commit diff
        print("Reading fix commit diff...", flush=True)
        fix_diff = get_fix_commit_diff(tmpdir, fix_sha)
        (out_dir / "fix_commit_diff.txt").write_text(fix_diff)
        print(f"  Fix diff: {len(fix_diff.splitlines())} lines")

        # 2. Get details for all blame commits; do deep log trace if sparse
        if len(blame_commits) <= 1:
            print(f"Phase2 blame sparse ({len(blame_commits)}), running deep git log trace...", flush=True)
            traced = deep_log_trace(tmpdir, candidate["files"], fix_sha)
            if traced:
                print(f"  Deep trace found {len(traced)} commits in file history")
                blame_commits = list(dict.fromkeys(blame_commits + traced))
            else:
                print("  Deep trace found nothing — single-commit pattern likely")

        print(f"Fetching details for {len(blame_commits)} blame commits...", flush=True)
        all_commit_details = []
        for sha in blame_commits:
            d = get_commit_detail(tmpdir, sha)
            if "error" not in d:
                all_commit_details.append(d)
        all_commit_details.sort(key=lambda x: x.get("date", ""))
        (out_dir / "all_blame_commits.json").write_text(
            json.dumps(all_commit_details, indent=2)
        )
        print(f"  Got details for {len(all_commit_details)} commits")

        # 3. Identify key commits
        print("Identifying key introducing commits...", flush=True)
        key_commits = identify_key_commits(
            tmpdir, blame_commits, candidate["files"], fix_sha
        )
        print(f"  Key commits identified: {len(key_commits)}")
        for kc in key_commits:
            print(f"    {kc['short_sha']}  {kc['date'][:10]}  {kc['subject'][:60]}")

        # 4. For each key commit, get the file-level diffs for the relevant files
        print("Fetching per-file diffs for key commits...", flush=True)
        key_commit_diffs = {}
        for kc in key_commits:
            sha = kc["sha"]
            diffs = {}
            for f in candidate["files"]:
                fname = f["filename"]
                if fname in kc["files_changed"]:
                    diff = get_file_diff_at_commit(tmpdir, sha, fname)
                    if diff:
                        diffs[fname] = diff
            key_commit_diffs[sha] = diffs
            if diffs:
                print(f"    {kc['short_sha']}: diffs for {list(diffs.keys())[:2]}")

        (out_dir / "key_commit_diffs.json").write_text(
            json.dumps({
                "key_commits": key_commits,
                "diffs_by_commit": {k: v for k, v in key_commit_diffs.items()},
            }, indent=2)
        )

        # 5. Build annotation skeleton
        annotation = build_annotation(candidate, key_commits, tmpdir)
        annotation_path = dataset_dir / "annotation.json"
        annotation_path.write_text(json.dumps(annotation, indent=2))
        print(f"\nAnnotation skeleton → {annotation_path}")

        # 6. Write reproduction.md
        repro_lines = [
            f"# Reproduction: {cve_id}",
            f"",
            f"**Summary:** {candidate['summary']}",
            f"**Repo:** {candidate['repo']}",
            f"**Fix commit:** `{fix_sha}`",
            f"**CWEs:** {candidate['cwe_ids']}",
            f"",
            f"## Contributing commits",
            f"",
        ]
        for i, kc in enumerate(key_commits, 1):
            repro_lines += [
                f"### Commit {i}: `{kc['short_sha']}` ({kc['date'][:10]})",
                f"**Author:** {kc['author']}",
                f"**Message:** {kc['subject']}",
                f"**Files:** {', '.join(kc['files_changed'][:5])}",
                f"",
                f"```bash",
                f"git clone {candidate['repo']} /tmp/{repo_name}",
                f"cd /tmp/{repo_name}",
                f"git checkout {kc['sha']}",
                f"# Run SAST on this state — expected: no relevant finding",
                f"semgrep --config auto --json -o /tmp/semgrep_{cve_id}_{kc['short_sha']}.json .",
                f"bandit -r . -f json -o /tmp/bandit_{cve_id}_{kc['short_sha']}.json",
                f"```",
                f"",
            ]
        repro_lines += [
            f"## Verification (vulnerable state = just before fix)",
            f"",
            f"```bash",
            f"cd /tmp/{repo_name}",
            f"git checkout {fix_sha}^  # state just before fix",
            f"# At this point the vulnerability exists — both commits combined",
            f"semgrep --config auto --json -o /tmp/semgrep_{cve_id}_prefixstate.json .",
            f"bandit -r . -f json -o /tmp/bandit_{cve_id}_prefixstate.json",
            f"```",
            f"",
            f"## Fix",
            f"",
            f"```bash",
            f"git checkout {fix_sha}",
            f"git show {fix_sha} --stat",
            f"```",
            f"",
            f"---",
            f"*TODO: fill in isolated_severity per commit after running SAST above*",
        ]
        (dataset_dir / "reproduction.md").write_text("\n".join(repro_lines))
        print(f"Reproduction guide  → {dataset_dir / 'reproduction.md'}")

        return True

    except Exception as e:
        print(f"Error: {e}", flush=True)
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", nargs="+", help="Specific CVE IDs to analyse")
    parser.add_argument("--top", type=int, default=5,
                        help="Auto-pick top N by blame commits (2-20 range, skip outliers)")
    parser.add_argument("--force", action="store_true",
                        help="Process candidates even if multi_commit_confirmed=false (uses deep log trace)")
    args = parser.parse_args()

    if not RANKED.exists():
        print(f"Error: {RANKED} not found. Run mine_candidates.py --phase 2 first.")
        sys.exit(1)

    all_candidates = json.loads(RANKED.read_text())
    confirmed = [c for c in all_candidates if c.get("multi_commit_confirmed")] if not args.force else all_candidates

    if args.cves:
        targets = [c for c in confirmed if c["cve_id"] in args.cves]
        if args.force:
            # Also pick any from all_candidates not yet in confirmed
            found_ids = {c["cve_id"] for c in targets}
            for c in all_candidates:
                if c["cve_id"] in args.cves and c["cve_id"] not in found_ids:
                    targets.append(c)
        missing = set(args.cves) - {c["cve_id"] for c in targets}
        if missing:
            print(f"Warning: CVEs not found in candidates list: {missing}")
    else:
        # Auto-pick: exclude outliers (>25 blame commits = likely repo-wide refactor)
        # and sort by 2-15 range (cleanest stories)
        reasonable = [
            c for c in confirmed
            if 2 <= (c.get("distinct_blame_commits") or 0) <= 20
        ]
        reasonable.sort(key=lambda x: -(x.get("distinct_blame_commits") or 0))
        targets = reasonable[:args.top]

    print(f"\nTargets for archaeology ({len(targets)}):")
    for t in targets:
        n = t.get('distinct_blame_commits') or '?'
        print(f"  {t['cve_id']:22} commits={n!s:>3}  {t['owner']}/{t['repo_name']}")

    results = {}
    for candidate in targets:
        ok = analyse_cve(candidate)
        results[candidate["cve_id"]] = "ok" if ok else "failed"

    print(f"\n{'='*60}")
    print("Archaeology complete")
    print(f"{'='*60}")
    for cve_id, status in results.items():
        print(f"  {cve_id}: {status}")
    print(f"\nAnnotation skeletons in: {DATASET}")
    print(f"Full diff data in:        {ARCH_DIR}")
    print(f"\nNext step (CVB-S5): review annotation.json files, fill in")
    print(f"  vulnerability_chain.description and isolated_severity fields.")


if __name__ == "__main__":
    main()
