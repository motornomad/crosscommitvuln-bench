#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — Annotation Schema Validator (CVB-1c)

Validates all annotation.json files against the canonical schema.
Exits non-zero if any file fails validation.

Usage:
  python scripts/validate_annotations.py              # validate all
  python scripts/validate_annotations.py CVE-2026-27602  # validate one
  python scripts/validate_annotations.py --summary    # print status table only
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATASET = ROOT / "dataset"

# ── Schema ────────────────────────────────────────────────────────────────────

REQUIRED_TOP_LEVEL = {
    "cve_id": str,
    "repo": str,
    "ecosystem": str,
    "severity_combined": str,
    "fix_commit": str,
    "contributing_commits": list,
    "vulnerability_chain": dict,
    "annotation_status": str,
    "commit_span_days": (int, float),
}

REQUIRED_COMMIT_FIELDS = {
    "hash": str,
    "short_hash": str,
    "date": str,
    "author": str,
    "subject": str,
    "files_changed": list,
    "isolated_severity": str,
    "isolated_severity_note": str,
    "semgrep_findings": list,
    "bandit_findings": list,
}

REQUIRED_CHAIN_FIELDS = {
    "description": str,
    "attack_vector": str,
    "exploitability": str,
    "why_sast_misses_per_commit": str,
}

VALID_STATUSES = {
    "complete",
    "complete+sast",
    "complete+agent",
    "complete+sast+agent",
    "partial — ambiguous chain",
}
SKIP_PREFIX = "SKIP"

VALID_SEVERITIES = {"low", "medium", "high", "benign"}
VALID_EXPLOITABILITY = {"high", "medium", "low", "TODO: high/medium/low"}

PLACEHOLDER_STRINGS = {
    "TODO",
    "TODO: describe the chain",
    "TODO: verify by running semgrep/bandit on this commit",
    "TODO: explain why each commit individually looks benign to SAST",
    "skeleton — needs human review",
}


# ── Validation Logic ──────────────────────────────────────────────────────────

class ValidationError(Exception):
    pass


def check_no_placeholder(value: str, field: str):
    for ph in PLACEHOLDER_STRINGS:
        if value.strip().startswith(ph):
            raise ValidationError(f"Field '{field}' still contains placeholder: {value[:60]!r}")


def validate_annotation(data: dict, path: Path) -> list[str]:
    """Return list of error strings. Empty = valid."""
    errors = []

    def err(msg):
        errors.append(f"{path.parent.name}: {msg}")

    # Top-level required fields
    for field, expected_type in REQUIRED_TOP_LEVEL.items():
        if field not in data:
            err(f"Missing required field: '{field}'")
            continue
        val = data[field]
        if isinstance(expected_type, tuple):
            if not isinstance(val, expected_type):
                err(f"Field '{field}' must be one of {expected_type}, got {type(val).__name__}")
        else:
            if not isinstance(val, expected_type):
                err(f"Field '{field}' must be {expected_type.__name__}, got {type(val).__name__}")

    if errors:
        return errors  # can't continue without basics

    # annotation_status
    status = data["annotation_status"]
    if not status.startswith(SKIP_PREFIX) and status not in VALID_STATUSES:
        err(f"annotation_status '{status}' is not a recognised value. Use: {VALID_STATUSES} or start with 'SKIP'")

    # If SKIP, no further validation needed
    if status.startswith(SKIP_PREFIX):
        return errors

    # commit_span_days
    span = data.get("commit_span_days")
    if span is not None and span < 0:
        err("commit_span_days must be >= 0")

    # contributing_commits
    commits = data.get("contributing_commits", [])
    if len(commits) < 2:
        err(f"contributing_commits must have >= 2 entries for a multi-commit vuln (has {len(commits)})")

    for i, c in enumerate(commits):
        prefix = f"contributing_commits[{i}]"
        for field, expected_type in REQUIRED_COMMIT_FIELDS.items():
            if field not in c:
                err(f"{prefix}: Missing field '{field}'")
                continue
            if not isinstance(c[field], expected_type):
                err(f"{prefix}: Field '{field}' must be {expected_type.__name__}")

        # Check isolated_severity is valid
        isev = c.get("isolated_severity", "")
        if isev not in VALID_SEVERITIES:
            err(f"{prefix}: isolated_severity '{isev}' not in {VALID_SEVERITIES}")

        # Check for unfilled TODO placeholders
        for field in ("isolated_severity_note",):
            val = c.get(field, "")
            if isinstance(val, str):
                try:
                    check_no_placeholder(val, f"{prefix}.{field}")
                except ValidationError as e:
                    err(str(e))

        # Date format sanity (YYYY-MM-DD)
        date_str = c.get("date", "")
        if date_str and (len(date_str) < 10 or date_str[4] != "-" or date_str[7] != "-"):
            err(f"{prefix}: date '{date_str}' should be YYYY-MM-DD format")

        # hash length
        hash_val = c.get("hash", "")
        if hash_val and len(hash_val) < 7:
            err(f"{prefix}: hash '{hash_val}' looks too short")

    # vulnerability_chain
    chain = data.get("vulnerability_chain", {})
    for field, expected_type in REQUIRED_CHAIN_FIELDS.items():
        if field not in chain:
            err(f"vulnerability_chain: Missing field '{field}'")
            continue
        val = chain[field]
        if not isinstance(val, expected_type):
            err(f"vulnerability_chain.{field} must be {expected_type.__name__}")

    # Check chain fields for placeholders
    for field in ("description", "why_sast_misses_per_commit"):
        val = chain.get(field, "")
        if isinstance(val, str):
            try:
                check_no_placeholder(val, f"vulnerability_chain.{field}")
            except ValidationError as e:
                err(str(e))

    expl = chain.get("exploitability", "")
    if expl not in VALID_EXPLOITABILITY:
        err(f"vulnerability_chain.exploitability '{expl}' not in {VALID_EXPLOITABILITY}")

    # Chain description should be substantive (>100 chars)
    desc = chain.get("description", "")
    if len(desc) < 100:
        err(f"vulnerability_chain.description is too short ({len(desc)} chars) — must describe the actual chain")

    # CWE field (optional but recommended)
    if "cve_id" in data and not data.get("cwe_ids") and not data.get("cwe"):
        # Just a warning, not an error
        pass

    return errors


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cves", nargs="*", help="Specific CVE IDs to validate (default: all)")
    parser.add_argument("--summary", action="store_true", help="Print status table only (no error details)")
    parser.add_argument("--strict", action="store_true", help="Treat SKIP annotations as warnings too")
    args = parser.parse_args()

    # Collect annotation files
    if args.cves:
        paths = [DATASET / cve / "annotation.json" for cve in args.cves]
    else:
        paths = sorted(DATASET.glob("*/annotation.json"))

    if not paths:
        print("No annotation.json files found.")
        sys.exit(1)

    all_errors: dict[str, list[str]] = {}
    status_table: list[tuple[str, str, str, int]] = []

    for p in paths:
        if not p.exists():
            all_errors[p.parent.name] = [f"File not found: {p}"]
            status_table.append((p.parent.name, "MISSING", "—", 0))
            continue

        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            all_errors[p.parent.name] = [f"JSON parse error: {e}"]
            status_table.append((p.parent.name, "PARSE_ERROR", "—", 0))
            continue

        errors = validate_annotation(data, p)
        status = data.get("annotation_status", "unknown")
        span = data.get("commit_span_days", "?")
        n_commits = len(data.get("contributing_commits", []))

        if errors:
            all_errors[p.parent.name] = errors
            icon = "✗"
        elif status.startswith("SKIP"):
            icon = "⊘"
        else:
            icon = "✓"

        status_table.append((p.parent.name, icon, status, span))

    # Print summary table
    complete = sum(1 for _, icon, _, _ in status_table if icon == "✓")
    skipped = sum(1 for _, icon, _, _ in status_table if icon == "⊘")
    failed = sum(1 for _, icon, _, _ in status_table if icon == "✗")

    print(f"\n{'CVE':25} {'':3} {'Status':40} {'Span':>8}")
    print("-" * 80)
    for cve, icon, status, span in status_table:
        print(f"{cve:25} {icon:3} {status[:40]:40} {str(span):>8}")

    print("-" * 80)
    print(f"Total: {len(status_table)}  ✓ Complete: {complete}  ⊘ Skip: {skipped}  ✗ Errors: {failed}")
    print()

    # Print errors
    if not args.summary and all_errors:
        print("=== Validation Errors ===")
        for cve_id, errs in all_errors.items():
            for e in errs:
                print(f"  ERROR  {e}")
        print()

    # Exit code
    if failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
