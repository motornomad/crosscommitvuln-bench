#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — Baseline SAST Evaluation (CVB-S6/S7/S8)

For each annotated CVE:
  For each contributing commit (PER-COMMIT scan):
    - git checkout <contributing_commit>
    - run semgrep --config auto
    - run bandit -r
    - record: did either tool flag anything related to the eventual CVE?
  For the pre-fix state (CUMULATIVE scan):
    - git checkout <fix_commit>^
    - run both tools again
    - record: does the tool catch it when all commits are present?

Outputs:
  - results/baseline_results.json          full per-CVE per-commit findings
  - results/baseline_summary.json          CCDR / CDR / detection gap metrics
  - annotation.json updated in-place with semgrep_findings / bandit_findings

Usage:
  python scripts/run_baselines.py
  python scripts/run_baselines.py --cves CVE-2026-27602 CVE-2026-32247
  python scripts/run_baselines.py --dry-run   # show plan, no SAST execution
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
DATASET = ROOT / "dataset"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

SEMGREP = "/home/arunabh_majumdar/postura/.venv/bin/semgrep"
BANDIT = "/home/arunabh_majumdar/postura/.venv/bin/bandit"
PYTHON = "/home/arunabh_majumdar/postura/.venv/bin/python"

# ── SAST runners ─────────────────────────────────────────────────────────────

def run_semgrep(repo_dir: str, timeout: int = 180) -> list[dict]:
    """
    Run semgrep --config auto on repo_dir.
    Returns list of finding dicts: {rule_id, path, line, message, severity}.
    """
    try:
        r = subprocess.run(
            [SEMGREP, "--config", "auto", "--json", "--quiet",
             "--no-git-ignore",  # scan all files regardless of .gitignore
             "--timeout", "30",  # per-rule timeout
             "."],
            cwd=repo_dir,
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
        if r.returncode not in (0, 1):  # 0=no findings, 1=findings found
            return [{"error": f"semgrep exit {r.returncode}: {r.stderr[:200]}"}]
        data = json.loads(r.stdout) if r.stdout.strip() else {"results": []}
        findings = []
        for result in data.get("results", []):
            findings.append({
                "rule_id": result.get("check_id", ""),
                "path": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "message": result.get("extra", {}).get("message", "")[:200],
                "severity": result.get("extra", {}).get("severity", ""),
            })
        return findings
    except subprocess.TimeoutExpired:
        return [{"error": "semgrep timeout"}]
    except json.JSONDecodeError as e:
        return [{"error": f"semgrep json parse error: {e}"}]
    except Exception as e:
        return [{"error": str(e)}]


def run_bandit(repo_dir: str, timeout: int = 120) -> list[dict]:
    """
    Run bandit -r on repo_dir.
    Returns list of finding dicts: {test_id, filename, line, issue_text, severity, confidence}.
    """
    try:
        r = subprocess.run(
            [BANDIT, "-r", ".", "-f", "json", "-q"],
            cwd=repo_dir,
            capture_output=True, text=True, timeout=timeout,
        )
        # bandit exits non-zero if findings exist — that's normal
        output = r.stdout.strip()
        if not output:
            return []
        data = json.loads(output)
        findings = []
        for result in data.get("results", []):
            findings.append({
                "test_id": result.get("test_id", ""),
                "test_name": result.get("test_name", ""),
                "filename": result.get("filename", ""),
                "line": result.get("line_number", 0),
                "issue_text": result.get("issue_text", "")[:200],
                "severity": result.get("issue_severity", ""),
                "confidence": result.get("issue_confidence", ""),
            })
        return findings
    except subprocess.TimeoutExpired:
        return [{"error": "bandit timeout"}]
    except json.JSONDecodeError:
        return []
    except Exception as e:
        return [{"error": str(e)}]


# ── Relevance classifier ──────────────────────────────────────────────────────

def is_relevant_finding(finding: dict, cve: dict) -> bool:
    """
    Heuristic: is this finding plausibly related to the CVE's vulnerability?
    Uses CWE-to-rule mappings and file path matching.
    Conservative: prefer false negatives over false positives.
    """
    cwe_ids = [c.replace("CWE-", "") for c in cve.get("cwe_ids", [])]
    summary = cve.get("summary", "").lower()
    fix_files = {f["filename"] for f in cve.get("files", [])}

    # CWE → specific bandit test IDs and semgrep rule keywords that DIRECTLY
    # indicate the vulnerability class. Intentionally narrow — B101 (assert),
    # B324 (sha1), B404 (subprocess import) are too generic and excluded.
    cwe_direct_tests = {
        # OS command injection — only shell=True or string-arg subprocess calls
        "78":  {"B602", "B604", "B605", "B606", "B607"},
        # Path traversal — only dedicated path traversal checks (not B101/B324)
        "22":  {"B612"},
        # SQL injection
        "89":  {"B608"},
        # Injection (generic/Cypher) — B608 covers string-based query construction
        "943": {"B608"},
        # Code injection / eval
        "94":  {"B102", "B307"},
        # Template injection / Jinja2
        "1336":{"B701"},
        # Weak crypto / padding oracle
        "203": {"B505"},
        "327": {"B303", "B304", "B305", "B413"},
        # Missing auth
        "306": {"B105", "B106"},
    }

    # Semgrep rule keyword hints (rule_id substring match)
    cwe_semgrep_hints = {
        "78":  ["command-injection", "shell-injection", "subprocess-shell"],
        "22":  ["path-traversal", "directory-traversal"],
        "89":  ["sql-injection", "sqli"],
        "943": ["injection", "cypher"],
        "94":  ["code-injection", "eval"],
        "1336":["template-injection", "jinja"],
        "327": ["weak-crypto", "rsa1", "pkcs1"],
        "306": ["missing-auth", "authentication"],
    }

    test_id = (finding.get("test_id") or "").upper()
    rule_id = (finding.get("rule_id") or "").lower()
    path = (finding.get("path") or finding.get("filename") or "")
    sev = (finding.get("severity") or "").upper()
    conf = (finding.get("confidence") or "").upper()

    # Must be at least MEDIUM confidence for bandit
    if test_id and conf == "LOW":
        return False

    for cwe in cwe_ids:
        # Bandit: exact test_id match against the CWE's known tests
        if test_id in cwe_direct_tests.get(cwe, set()):
            # Also require that the finding is in a relevant source file,
            # not a test file or deploy script
            path_lower = path.lower()
            if any(x in path_lower for x in ["/test", "deploy.py", "setup.py", "conftest"]):
                continue
            return True

        # Semgrep: rule_id keyword match
        for hint in cwe_semgrep_hints.get(cwe, []):
            if hint in rule_id:
                return True

    return False


# ── Clone + checkout + scan ───────────────────────────────────────────────────

def scan_commit(
    owner: str, repo_name: str, commit_sha: str, label: str,
    tmpdir: str, cve: dict, dry_run: bool = False,
) -> dict:
    """
    Checkout commit_sha in tmpdir (already cloned), run semgrep + bandit, return results.
    """
    print(f"    [{label}] {commit_sha[:8]}...", flush=True)
    if dry_run:
        return {"label": label, "sha": commit_sha[:8], "dry_run": True,
                "semgrep": [], "bandit": [], "relevant_semgrep": [],
                "relevant_bandit": [], "any_relevant": False}

    # Checkout the commit
    r = subprocess.run(
        ["git", "checkout", "--quiet", commit_sha],
        cwd=tmpdir, capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        print(f"      checkout failed: {r.stderr.strip()[:100]}", flush=True)
        return {"label": label, "sha": commit_sha[:8], "error": "checkout_failed",
                "semgrep": [], "bandit": [], "relevant_semgrep": [],
                "relevant_bandit": [], "any_relevant": False}

    # Run SAST tools
    semgrep_findings = run_semgrep(tmpdir)
    bandit_findings = run_bandit(tmpdir)

    relevant_semgrep = [f for f in semgrep_findings if is_relevant_finding(f, cve)]
    relevant_bandit = [f for f in bandit_findings if is_relevant_finding(f, cve)]
    any_relevant = bool(relevant_semgrep or relevant_bandit)

    total_s = len([f for f in semgrep_findings if "error" not in f])
    total_b = len([f for f in bandit_findings if "error" not in f])
    rel_s = len(relevant_semgrep)
    rel_b = len(relevant_bandit)

    flag = "⚠ RELEVANT FINDING" if any_relevant else "✓ no relevant findings"
    print(f"      semgrep: {total_s} total, {rel_s} relevant | "
          f"bandit: {total_b} total, {rel_b} relevant  {flag}", flush=True)

    return {
        "label": label,
        "sha": commit_sha[:8],
        "semgrep_total": total_s,
        "bandit_total": total_b,
        "relevant_semgrep": relevant_semgrep,
        "relevant_bandit": relevant_bandit,
        "any_relevant": any_relevant,
    }


def evaluate_cve(annotation_path: Path, dry_run: bool = False) -> dict:
    """Run per-commit and cumulative SAST on one annotated CVE."""
    annotation = json.loads(annotation_path.read_text())
    cve_id = annotation["cve_id"]
    owner = annotation["repo"].split("github.com/")[1].split("/")[0]
    repo_name = annotation["repo"].split("github.com/")[1].split("/")[1]
    fix_sha = annotation["fix_commit"]
    contributing = annotation["contributing_commits"]

    print(f"\n{'='*60}")
    print(f"{cve_id}  ({annotation.get('severity_combined', annotation.get('severity',''))})  {owner}/{repo_name}")
    print(f"CWEs: {annotation['cwe_ids']}")
    print(f"Contributing commits: {len(contributing)}")
    print(f"{'='*60}")

    result = {
        "cve_id": cve_id,
        "severity": annotation.get("severity_combined", annotation.get("severity", "")),
        "cwe_ids": annotation["cwe_ids"],
        "per_commit_scans": [],
        "cumulative_scan": None,
        "ccdr_this_cve": False,   # did per-commit SAST catch it?
        "cdr_this_cve": False,    # did cumulative SAST catch it?
    }

    tmpdir = tempfile.mkdtemp(prefix=f"ccvb_{cve_id}_")
    try:
        clone_url = f"https://github.com/{owner}/{repo_name}.git"
        print(f"Cloning (depth=500)...", flush=True)
        if not dry_run:
            r = subprocess.run(
                ["git", "clone", "--depth=500", "--quiet", clone_url, tmpdir],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode != 0:
                print(f"Clone failed: {r.stderr[:150]}", flush=True)
                return result
            # Fetch fix commit
            subprocess.run(
                ["git", "fetch", "--depth=500", "origin", fix_sha],
                cwd=tmpdir, capture_output=True, timeout=60,
            )

        # --- Per-commit scans ---
        print("\n  Per-commit scans (simulating CI/CD pipeline):")
        for commit in contributing:
            sha = commit["hash"]
            subject = commit["subject"][:50]
            label = f"per-commit: {commit['short_hash']} ({subject})"
            scan = scan_commit(owner, repo_name, sha, label, tmpdir, annotation, dry_run)
            result["per_commit_scans"].append(scan)
            if scan.get("any_relevant"):
                result["ccdr_this_cve"] = True

        # --- Cumulative scan (pre-fix state = all contributing commits applied) ---
        print(f"\n  Cumulative scan (pre-fix state: {fix_sha[:8]}^):")
        # get parent of fix commit
        if not dry_run:
            r = subprocess.run(
                ["git", "rev-parse", f"{fix_sha}^"],
                cwd=tmpdir, capture_output=True, text=True, timeout=10,
            )
            pre_fix = r.stdout.strip() if r.returncode == 0 else fix_sha
        else:
            pre_fix = fix_sha + "_parent"

        cumulative = scan_commit(
            owner, repo_name, pre_fix, "cumulative (pre-fix state)",
            tmpdir, annotation, dry_run,
        )
        result["cumulative_scan"] = cumulative
        if cumulative.get("any_relevant"):
            result["cdr_this_cve"] = True

        # Annotate the per-commit results back into annotation.json
        if not dry_run:
            for i, commit in enumerate(contributing):
                if i < len(result["per_commit_scans"]):
                    scan = result["per_commit_scans"][i]
                    commit["semgrep_findings"] = scan.get("relevant_semgrep", [])
                    commit["bandit_findings"] = scan.get("relevant_bandit", [])
                    commit["sast_flagged_relevant"] = scan.get("any_relevant", False)
            annotation["cumulative_scan"] = cumulative
            annotation["ccdr_this_cve"] = result["ccdr_this_cve"]
            annotation["cdr_this_cve"] = result["cdr_this_cve"]
            annotation["annotation_status"] = "complete+sast"
            annotation_path.write_text(json.dumps(annotation, indent=2))

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    per_commit_flagged = "YES ⚠" if result["ccdr_this_cve"] else "NO ✓"
    cumulative_flagged = "YES ⚠" if result["cdr_this_cve"] else "NO ✓"
    print(f"\n  Per-commit SAST caught it:   {per_commit_flagged}")
    print(f"  Cumulative SAST caught it:   {cumulative_flagged}")

    return result


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(results: list[dict]) -> dict:
    """Compute CCDR, CDR, detection gap across all evaluated CVEs."""
    n = len(results)
    if n == 0:
        return {}

    ccdr_hits = sum(1 for r in results if r.get("ccdr_this_cve"))
    cdr_hits = sum(1 for r in results if r.get("cdr_this_cve"))

    ccdr = ccdr_hits / n
    cdr = cdr_hits / n
    gap = cdr - ccdr

    return {
        "n_cves": n,
        "ccdr_hits": ccdr_hits,
        "cdr_hits": cdr_hits,
        "CCDR": round(ccdr, 3),
        "CDR": round(cdr, 3),
        "detection_gap": round(gap, 3),
        "interpretation": (
            f"Per-commit SAST detected {ccdr_hits}/{n} CVEs ({ccdr*100:.0f}%). "
            f"Cumulative SAST detected {cdr_hits}/{n} ({cdr*100:.0f}%). "
            f"Detection gap = {gap*100:.0f}% — the gap cross-commit analysis fills."
        ),
    }


def print_summary(results: list[dict], metrics: dict):
    print(f"\n{'='*60}")
    print("BASELINE EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"\n{'CVE':22} {'Per-commit':14} {'Cumulative':14} {'Severity'}")
    print("-" * 65)
    for r in results:
        pc = "CAUGHT ⚠" if r.get("ccdr_this_cve") else "missed ✓"
        cu = "CAUGHT ⚠" if r.get("cdr_this_cve") else "missed ✓"
        print(f"{r['cve_id']:22} {pc:14} {cu:14} {r.get('severity_combined', r.get('severity',''))}")

    print(f"\n{'─'*65}")
    print(f"CCDR (per-commit detection rate): {metrics.get('CCDR', 0)*100:.0f}%  "
          f"({metrics.get('ccdr_hits', 0)}/{metrics.get('n_cves', 0)} CVEs caught per-commit)")
    print(f"CDR  (cumulative detection rate):  {metrics.get('CDR', 0)*100:.0f}%  "
          f"({metrics.get('cdr_hits', 0)}/{metrics.get('n_cves', 0)} CVEs caught on final state)")
    print(f"Detection gap:                     {metrics.get('detection_gap', 0)*100:.0f}%")
    print(f"\n{metrics.get('interpretation', '')}")
    print(f"\nKey claim: {metrics.get('CCDR',0)*100:.0f}% of these CVEs are INVISIBLE to "
          f"per-commit SAST — the core finding of the paper.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", nargs="+", help="Specific CVE IDs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without running SAST")
    args = parser.parse_args()

    # Collect annotated CVEs
    annotation_paths = []
    if args.cves:
        for cve_id in args.cves:
            p = DATASET / cve_id / "annotation.json"
            if p.exists():
                annotation_paths.append(p)
            else:
                print(f"Warning: {p} not found, skipping")
    else:
        annotation_paths = sorted(DATASET.glob("*/annotation.json"))

    if not annotation_paths:
        print("No annotation.json files found. Run archaeology.py first.")
        sys.exit(1)

    print(f"Evaluating {len(annotation_paths)} CVEs: "
          f"{[p.parent.name for p in annotation_paths]}")
    if args.dry_run:
        print("DRY RUN — SAST tools will not be executed\n")

    all_results = []
    for ann_path in annotation_paths:
        result = evaluate_cve(ann_path, dry_run=args.dry_run)
        all_results.append(result)

    metrics = compute_metrics(all_results)
    print_summary(all_results, metrics)

    # Save outputs
    (RESULTS / "baseline_results.json").write_text(
        json.dumps(all_results, indent=2))
    (RESULTS / "baseline_summary.json").write_text(
        json.dumps({"metrics": metrics, "per_cve": all_results}, indent=2))

    print(f"\nSaved:")
    print(f"  {RESULTS / 'baseline_results.json'}")
    print(f"  {RESULTS / 'baseline_summary.json'}")


if __name__ == "__main__":
    main()
