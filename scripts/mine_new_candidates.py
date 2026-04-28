#!/usr/bin/env python3
"""
Mine new CVE candidates from OSV API and run git blame archaeology.
Saves confirmed multi-commit candidates to results/new_candidates.json
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

EXISTING_CVES = {
    # original 15 paper CVEs
    "CVE-2025-10155", "CVE-2025-10156", "CVE-2025-10157", "CVE-2025-10283", "CVE-2025-14009",
    "CVE-2025-15346", "CVE-2025-32434", "CVE-2025-3248", "CVE-2025-43859", "CVE-2025-46724",
    "CVE-2025-5120", "CVE-2025-54950", "CVE-2025-55449", "CVE-2025-58367", "CVE-2025-61622",
    "CVE-2025-62593", "CVE-2025-64712", "CVE-2025-65015", "CVE-2025-68398", "CVE-2025-68664",
    "CVE-2025-69219", "CVE-2026-1669", "CVE-2026-22584", "CVE-2026-2472", "CVE-2026-25505",
    "CVE-2026-26198", "CVE-2026-26331", "CVE-2026-27483", "CVE-2026-27602", "CVE-2026-27614",
    "CVE-2026-27641", "CVE-2026-27696", "CVE-2026-27825", "CVE-2026-27826", "CVE-2026-27953",
    "CVE-2026-27962", "CVE-2026-28416", "CVE-2026-28490", "CVE-2026-29065", "CVE-2026-32247",
    "CVE-2026-32274", "CVE-2026-32611", "CVE-2026-32711", "CVE-2026-33017", "CVE-2026-33046",
    "CVE-2026-33057", "CVE-2026-33154", "CVE-2026-33155", "CVE-2026-33310",
    # 2024 additions
    "CVE-2024-0520", "CVE-2024-1728", "CVE-2024-2912", "CVE-2024-3573", "CVE-2024-36039",
    # 2025 additions
    "CVE-2025-23042", "CVE-2025-27520",
    # 2026 additions (2026-04-28 batch 1)
    "CVE-2026-33053", "CVE-2026-2415", "CVE-2026-29039", "CVE-2026-28681", "CVE-2026-27194",
    "CVE-2026-30922", "CVE-2026-28498", "CVE-2026-24708", "CVE-2026-28518", "CVE-2026-26209",
    # 2026 additions (2026-04-28 batch 2)
    "CVE-2026-31958", "CVE-2026-28802", "CVE-2026-27932", "CVE-2026-27459", "CVE-2026-25990",
}

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN  = "https://api.osv.dev/v1/vulns/{}"

POPULAR_PACKAGES = [
    "django", "flask", "fastapi", "requests", "numpy", "pandas", "pillow",
    "sqlalchemy", "celery", "paramiko", "cryptography", "pyjwt", "werkzeug",
    "aiohttp", "httpx", "boto3", "gunicorn", "uvicorn", "starlette",
    "pydantic", "tornado", "twisted", "scrapy", "ansible", "salt",
    "jupyter", "notebook", "ipython", "tensorflow", "transformers",
    "langchain", "openai", "anthropic", "pymongo", "redis", "grpcio",
    "lxml", "jinja2", "markupsafe", "click", "typer", "rich",
    "httplib2", "urllib3", "certifi", "pyopenssl", "paramiko",
    "yaml", "pyyaml", "toml", "protobuf", "grpc",
]

# ── CVSS score extractor ──────────────────────────────────────────────────────

def extract_cvss_score(severity_list: list) -> float:
    """Return the highest CVSS base score from OSV severity list."""
    best = 0.0
    for s in severity_list:
        score_str = s.get("score", "")
        # CVSS v3 vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = re.search(r"/(\d+\.\d+)$", score_str)
        if m:
            best = max(best, float(m.group(1)))
            continue
        # Sometimes just a number
        try:
            best = max(best, float(score_str))
        except (ValueError, TypeError):
            pass
    return best


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ── OSV query ─────────────────────────────────────────────────────────────────

def query_osv_package(pkg: str) -> list[dict]:
    try:
        resp = requests.post(
            OSV_QUERY,
            json={"package": {"name": pkg, "ecosystem": "PyPI"}},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  [WARN] {pkg}: HTTP {resp.status_code}")
            return []
        return resp.json().get("vulns", [])
    except Exception as e:
        print(f"  [WARN] {pkg}: {e}")
        return []


def fetch_vuln_detail(vid: str) -> dict:
    """Fetch full vulnerability detail from OSV."""
    try:
        resp = requests.get(OSV_VULN.format(vid), timeout=30)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def extract_cwe_ids(vuln: dict) -> list[str]:
    """Extract CWE IDs from OSV database_specific or affected fields."""
    cwes = []
    # OSV sometimes has CWEs under database_specific
    db_spec = vuln.get("database_specific", {})
    for key in ("cwe_ids", "cwes"):
        val = db_spec.get(key, [])
        if isinstance(val, list):
            cwes.extend(val)
        elif isinstance(val, str):
            cwes.append(val)
    # Also check affected[].database_specific
    for aff in vuln.get("affected", []):
        db2 = aff.get("database_specific", {})
        for key in ("cwe_ids", "cwes"):
            val = db2.get(key, [])
            if isinstance(val, list):
                cwes.extend(val)
    # Deduplicate, keep CWE-NNN format
    seen = set()
    result = []
    for c in cwes:
        if c and c not in seen:
            seen.add(c)
            result.append(c)
    return result


def extract_ghsa_id(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("GHSA-"):
            return alias
    vid = vuln.get("id", "")
    if vid.startswith("GHSA-"):
        return vid
    return ""


def mine_osv() -> list[dict]:
    """Query OSV for PyPI CVEs. Return list of candidates with fix commits."""
    seen_ids: set[str] = set()
    results: list[dict] = []

    for pkg in POPULAR_PACKAGES:
        print(f"  Querying OSV: {pkg}", flush=True)
        vulns = query_osv_package(pkg)

        for v in vulns:
            vid = v.get("id", "")
            # Accept CVE-* ids; also accept GHSA that have CVE aliases
            cve_id = ""
            if vid.startswith("CVE-"):
                cve_id = vid
            else:
                for alias in v.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
            if not cve_id:
                continue
            if cve_id in EXISTING_CVES or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)

            # Filter: only 2020-2025
            published = v.get("published", "")
            year = int(published[:4]) if published and published[:4].isdigit() else 0
            if year < 2020 or year > 2025:
                continue

            # Find GitHub fix commits
            refs = v.get("references", [])
            fix_commits = []
            for r in refs:
                url = r.get("url", "")
                if "github.com" in url and "/commit/" in url and r.get("type") in ("FIX", "WEB", None, ""):
                    # Normalise: remove trailing slashes / query strings
                    clean = url.split("?")[0].rstrip("/")
                    fix_commits.append(clean)
            # Also look at fix-typed refs
            for r in refs:
                if r.get("type") == "FIX":
                    url = r.get("url", "")
                    if "github.com" in url and "/commit/" in url:
                        clean = url.split("?")[0].rstrip("/")
                        if clean not in fix_commits:
                            fix_commits.append(clean)

            if not fix_commits:
                continue

            # Fetch full detail for CVSS score and CWEs
            full = fetch_vuln_detail(vid) if vid != cve_id else v
            score = extract_cvss_score(full.get("severity", []) or v.get("severity", []))
            sev = severity_label(score)

            # Only high/critical
            if sev not in ("high", "critical"):
                continue

            ghsa = extract_ghsa_id(full or v)
            cwe_ids = extract_cwe_ids(full or v)

            # Parse owner/repo from first fix commit
            m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", fix_commits[0])
            if not m:
                continue
            owner, repo_name, fix_sha = m.group(1), m.group(2), m.group(3)

            results.append({
                "cve_id": cve_id,
                "ghsa_id": ghsa,
                "severity": sev,
                "cvss_score": score,
                "cwe_ids": cwe_ids,
                "summary": v.get("summary", full.get("summary", "")),
                "repo": f"https://github.com/{owner}/{repo_name}",
                "owner": owner,
                "repo_name": repo_name,
                "fix_commit": fix_sha,
                "fix_commit_url": fix_commits[0],
                "package": pkg,
                "published": published[:10],
            })
            print(f"    + {cve_id} ({sev}) {owner}/{repo_name}")

        time.sleep(0.4)

    # Sort: critical first, then high; within group by most recent
    results.sort(key=lambda x: (-x["cvss_score"], x["published"]), reverse=False)
    results.sort(key=lambda x: (0 if x["severity"] == "critical" else 1, -x["cvss_score"]))
    return results


# ── git archaeology ───────────────────────────────────────────────────────────

def git_out(args: list, cwd: str, timeout: int = 60) -> str:
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else ""


def get_changed_py_files(repo_dir: str, fix_sha: str) -> list[str]:
    """Return list of .py files changed by the fix commit."""
    out = git_out(
        ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", fix_sha],
        repo_dir,
    )
    return [f for f in out.splitlines() if f.endswith(".py")]


def blame_file_at_parent(repo_dir: str, fix_sha: str, filepath: str) -> list[str]:
    """Run git blame on filepath at fix_sha^ and return list of commit hashes."""
    parent = fix_sha + "^"
    # Check file exists at parent
    exists = git_out(["git", "ls-tree", "-r", "--name-only", parent], repo_dir)
    if filepath not in exists.splitlines():
        return []
    out = git_out(
        ["git", "blame", "--porcelain", parent, "--", filepath],
        repo_dir,
        timeout=60,
    )
    hashes = []
    for line in out.splitlines():
        # porcelain format: 40-char hash at start of attribution lines
        if re.match(r"^[0-9a-f]{40} ", line):
            h = line[:40]
            hashes.append(h)
    return hashes


def run_archaeology(candidate: dict) -> dict:
    """Clone repo, blame fixed files, count distinct commits. Return enriched candidate."""
    cve_id = candidate["cve_id"]
    owner = candidate["owner"]
    repo_name = candidate["repo_name"]
    fix_sha = candidate["fix_commit"]
    clone_url = f"https://github.com/{owner}/{repo_name}.git"

    print(f"\n  [{cve_id}] Cloning {owner}/{repo_name} ...", flush=True)
    tmpdir = tempfile.mkdtemp(prefix=f"ccvb_new_{cve_id}_")
    try:
        r = subprocess.run(
            ["git", "clone", "--depth=100", "--quiet", clone_url, tmpdir],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            print(f"    Clone failed: {r.stderr[:150]}")
            return {**candidate, "multi_commit_confirmed": False, "error": "clone_failed"}

        # Ensure fix commit is present (shallow clone might miss it)
        subprocess.run(
            ["git", "fetch", "--depth=100", "origin", fix_sha],
            cwd=tmpdir, capture_output=True, timeout=60,
        )

        # Verify fix commit exists
        verify = git_out(["git", "cat-file", "-t", fix_sha], tmpdir)
        if verify != "commit":
            print(f"    Fix commit {fix_sha[:8]} not found in shallow clone")
            return {**candidate, "multi_commit_confirmed": False, "error": "fix_commit_not_found"}

        # Get changed py files
        py_files = get_changed_py_files(tmpdir, fix_sha)
        if not py_files:
            print(f"    No .py files changed in fix commit")
            return {**candidate, "multi_commit_confirmed": False, "py_files_changed": 0,
                    "error": "no_py_files"}

        print(f"    Fix touches {len(py_files)} py files: {py_files[:3]}", flush=True)

        # Blame each file at fix_sha^
        all_blame_hashes: set[str] = set()
        file_blame_counts = {}
        for fp in py_files[:5]:  # max 5 files
            hashes = blame_file_at_parent(tmpdir, fix_sha, fp)
            # Filter out zero-hashes (uncommitted)
            hashes = [h for h in hashes if h != "0" * 40]
            unique = set(hashes)
            all_blame_hashes.update(unique)
            file_blame_counts[fp] = len(unique)
            print(f"      blame {fp}: {len(unique)} distinct commits", flush=True)

        distinct = len(all_blame_hashes)
        multi_confirmed = distinct >= 2
        print(f"    Total distinct blame commits: {distinct}  → multi_commit={'YES' if multi_confirmed else 'NO'}")

        # Build file info
        files_info = []
        for fp in py_files[:5]:
            files_info.append({
                "filename": fp,
                "blame_commits": file_blame_counts.get(fp, 0),
            })

        return {
            **candidate,
            "multi_commit_confirmed": multi_confirmed,
            "distinct_blame_commits": distinct,
            "blame_commits": sorted(list(all_blame_hashes)),
            "files": files_info,
            "py_files_changed": len(py_files),
        }

    except subprocess.TimeoutExpired:
        print(f"    Timeout!")
        return {**candidate, "multi_commit_confirmed": False, "error": "timeout"}
    except Exception as e:
        print(f"    Error: {e}")
        return {**candidate, "multi_commit_confirmed": False, "error": str(e)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("CrossCommitVuln-Bench: Mining new candidates")
    print("=" * 60)

    # Step 1: Query OSV
    print("\n[STEP 1] Querying OSV API for PyPI CVEs...")
    candidates = mine_osv()
    print(f"\nFound {len(candidates)} new high/critical PyPI CVEs with GitHub fix commits")

    # Save raw results
    raw_path = RESULTS / "new_candidates_raw.json"
    raw_path.write_text(json.dumps(candidates, indent=2))
    print(f"Raw results → {raw_path}")

    if not candidates:
        print("No candidates found. Exiting.")
        return

    # Step 2: Archaeology on top candidates (up to 20, stop when we have 10+ confirmed)
    print(f"\n[STEP 2] Running git blame archaeology on top {min(20, len(candidates))} candidates...")
    confirmed_results = []
    all_results = []

    for cand in candidates[:20]:
        result = run_archaeology(cand)
        all_results.append(result)
        if result.get("multi_commit_confirmed"):
            confirmed_results.append(result)
            print(f"  ✓ CONFIRMED: {cand['cve_id']} ({len(confirmed_results)} so far)")
        if len(confirmed_results) >= 15:
            print("  Reached 15 confirmed — stopping early")
            break

    # Step 3: Save results
    out_path = RESULTS / "new_candidates.json"
    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"\nAll results → {out_path}")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total mined:         {len(candidates)}")
    print(f"Archaeology run on:  {len(all_results)}")
    print(f"Multi-commit confirmed: {len(confirmed_results)}")
    print(f"\nConfirmed candidates:")
    for r in confirmed_results:
        print(f"  {r['cve_id']:22} severity={r['severity']:8} blame_commits={r['distinct_blame_commits']:3}  {r['owner']}/{r['repo_name']}")

    # Also save confirmed-only subset
    confirmed_path = RESULTS / "new_candidates_confirmed.json"
    confirmed_path.write_text(json.dumps(confirmed_results, indent=2))
    print(f"\nConfirmed only → {confirmed_path}")


if __name__ == "__main__":
    main()
