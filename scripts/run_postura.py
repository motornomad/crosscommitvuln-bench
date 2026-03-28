#!/usr/bin/env python3
"""
CrossCommitVuln-Bench — POSTURA Sequential-Commit Evaluation (CVB-S11)

For each annotated CVE with accessible contributing commits:
  1. Clone repo at commit A state → run POSTURA taint analysis → record findings
  2. Clone repo at commit B state (all commits applied, pre-fix) → run POSTURA → record findings
  3. Key metric: does POSTURA fire a taint chain AFTER commit B that wasn't there after commit A?
     (Early detection: chain appears on commit B, not before)

Uses POSTURA's Python API directly — no Neo4j/Docker required for taint parsing.
Calls parse_file() per relevant file and checks for TaintFlow objects + inter-function chains.

Usage:
  python scripts/run_postura.py
  python scripts/run_postura.py --cves CVE-2026-27602 CVE-2025-10283
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
from dataclasses import asdict

# ── POSTURA on path ───────────────────────────────────────────────────────────
POSTURA_SRC = Path("/home/arunabh_majumdar/postura/src")
sys.path.insert(0, str(POSTURA_SRC))

from postura.ingest.ast_parser import parse_file                     # noqa: E402
from postura.models.ingest import TaintFlow, ASTNode, CallEdge       # noqa: E402

ROOT = Path(__file__).parent.parent
DATASET = ROOT / "dataset"
RESULTS = ROOT / "results"
POSTURA_RESULTS = RESULTS / "postura_eval"
POSTURA_RESULTS.mkdir(exist_ok=True)

# ── taint analysis helpers ────────────────────────────────────────────────────

def parse_py_files(repo_dir: str, py_files: list[str]) -> dict:
    """
    Run POSTURA parse_file() on py_files AND all .py files in their parent dirs.
    Wider scope is needed so inter-function chains can resolve callee taint flows
    (e.g. exec_cmd in sysutils.py needs to be parsed to detect subprocess sink).
    """
    all_nodes: list[ASTNode] = []
    all_edges: list[CallEdge] = []
    all_taint_flows: list[TaintFlow] = []

    # Collect: specified files + all .py files in the same directories
    to_parse: set[Path] = set()
    for fname in py_files:
        fpath = Path(repo_dir) / fname
        if fpath.exists():
            to_parse.add(fpath)
        # Also parse all .py files in the same directory (for callee resolution)
        parent = fpath.parent
        if parent.exists():
            to_parse.update(parent.glob("*.py"))

    for fpath in sorted(to_parse):
        try:
            nodes, edges, _accesses, _imports, taint_flows = parse_file(str(fpath))
            all_nodes.extend(nodes)
            all_edges.extend(edges)
            all_taint_flows.extend(taint_flows)
        except Exception as e:
            pass  # skip unparseable files silently

    # Nodes with confirmed taint sources (HTTP request reads)
    taint_source_nodes = [n for n in all_nodes if n.taint_sources]
    # Nodes with confirmed sink flows
    taint_sink_nodes = [n for n in all_nodes if getattr(n, "has_taint_flow", False)]

    return {
        "nodes": len(all_nodes),
        "edges": len(all_edges),
        "taint_flows": [
            {
                "function": tf.function_qualified_name,
                "source_param": tf.source_param,
                "source_type": tf.source_type,
                "sink_call": tf.sink_call,
                "sink_type": tf.sink_type,
                "sanitized": tf.sanitized,
                "source_line": tf.source_line,
                "sink_line": tf.sink_line,
                "file": tf.file,
            }
            for tf in all_taint_flows
        ],
        "taint_source_functions": [
            {"name": n.qualified_name, "sources": n.taint_sources, "file": n.file}
            for n in taint_source_nodes
        ],
        "inter_function_chains": detect_inter_function_chains(all_nodes, all_edges, all_taint_flows),
    }


def detect_inter_function_chains(
    nodes: list[ASTNode], edges: list[CallEdge], taint_flows: list[TaintFlow]
) -> list[dict]:
    """
    Replicate _rule_taint_inter_function logic in-memory (no Neo4j needed):
    Find: caller has taint_sources (HTTP request reads) AND calls callee that has taint flows.
    Returns list of chain dicts: {caller, callee, sink_type, evidence}.
    """
    # Build maps
    func_to_taint_flows: dict[str, list[TaintFlow]] = {}
    for tf in taint_flows:
        func_to_taint_flows.setdefault(tf.function_qualified_name, []).append(tf)

    taint_source_funcs: set[str] = {
        n.qualified_name for n in nodes if n.taint_sources
    }

    # Build call graph: caller → set of callees
    call_graph: dict[str, set[str]] = {}
    for edge in edges:
        call_graph.setdefault(edge.caller, set()).add(edge.callee)

    chains = []
    for caller in taint_source_funcs:
        for callee in call_graph.get(caller, set()):
            callee_flows = func_to_taint_flows.get(callee, [])
            if callee_flows:
                for tf in callee_flows:
                    chains.append({
                        "caller": caller,
                        "callee": callee,
                        "sink_type": tf.sink_type,
                        "sink_call": tf.sink_call,
                        "evidence": (
                            f"HTTP-sourced input in '{caller}' flows 1-hop to "
                            f"'{callee}' which reaches {tf.sink_call} ({tf.sink_type})"
                        ),
                    })

    return chains


# ── sequential commit evaluator ───────────────────────────────────────────────

def evaluate_cve_postura(annotation_path: Path) -> dict:
    annotation = json.loads(annotation_path.read_text())
    cve_id = annotation["cve_id"]
    owner = annotation["repo"].split("github.com/")[1].split("/")[0]
    repo_name = annotation["repo"].split("github.com/")[1].split("/")[1]
    fix_sha = annotation["fix_commit"]
    contributing = annotation["contributing_commits"]
    # Collect all Python files touched by contributing commits
    fix_files_set: set[str] = set()
    for commit in contributing:
        for f in commit.get("files_changed", []):
            if f.endswith(".py"):
                fix_files_set.add(f)
    fix_files = sorted(fix_files_set)

    print(f"\n{'='*60}")
    print(f"POSTURA eval: {cve_id}  ({annotation.get('severity_combined','')})  {owner}/{repo_name}")
    print(f"Relevant files ({len(fix_files)}): {fix_files[:4]}")
    print(f"{'='*60}")

    result = {
        "cve_id": cve_id,
        "severity": annotation.get("severity_combined", ""),
        "cwe_ids": annotation["cwe_ids"],
        "per_commit_results": [],
        "cumulative_result": None,
        "first_detection_commit": None,
        "detection_type": None,
        "postura_detected": False,
        "postura_detected_cumulative": False,
    }

    tmpdir = tempfile.mkdtemp(prefix=f"ccvb_postura_{cve_id}_")
    try:
        clone_url = f"https://github.com/{owner}/{repo_name}.git"
        print(f"Cloning (depth=500)...", flush=True)
        r = subprocess.run(
            ["git", "clone", "--depth=500", "--quiet", clone_url, tmpdir],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            print(f"Clone failed: {r.stderr[:150]}", flush=True)
            return result
        subprocess.run(
            ["git", "fetch", "--depth=500", "origin", fix_sha],
            cwd=tmpdir, capture_output=True, timeout=60,
        )

        # ── Per-commit scans ──────────────────────────────────────────────────
        print("\n  Per-commit POSTURA analysis:")
        for commit in contributing:
            sha = commit["hash"]
            short = commit["short_hash"]
            subj = commit["subject"][:50]

            r2 = subprocess.run(
                ["git", "checkout", "--quiet", sha],
                cwd=tmpdir, capture_output=True, text=True, timeout=30,
            )
            if r2.returncode != 0:
                print(f"    [{short}] checkout failed (commit too old for depth=500)", flush=True)
                result["per_commit_results"].append({
                    "sha": short, "subject": subj,
                    "status": "checkout_failed", "taint_flows": [],
                    "inter_function_chains": [], "detected": False,
                })
                continue

            print(f"    [{short}] {subj}...", flush=True)
            analysis = parse_py_files(tmpdir, fix_files)

            n_flows = len(analysis["taint_flows"])
            n_chains = len(analysis["inter_function_chains"])
            detected = n_flows > 0 or n_chains > 0

            status = "CHAIN DETECTED ⚠" if detected else "no chain ✓"
            print(f"      taint_flows={n_flows}  inter_func_chains={n_chains}  → {status}", flush=True)

            if detected and result["first_detection_commit"] is None:
                result["first_detection_commit"] = short
                result["detection_type"] = "intra" if n_flows > 0 else "inter_func"
                result["postura_detected"] = True

            for chain in analysis["inter_function_chains"][:2]:
                print(f"      CHAIN: {chain['evidence']}", flush=True)
            for tf in analysis["taint_flows"][:2]:
                print(f"      TAINT: {tf['function']} → {tf['sink_call']} ({tf['sink_type']})", flush=True)

            result["per_commit_results"].append({
                "sha": short, "subject": subj,
                "status": "ok",
                "taint_flows": analysis["taint_flows"],
                "inter_function_chains": analysis["inter_function_chains"],
                "detected": detected,
            })

        # ── Cumulative scan (pre-fix state) ───────────────────────────────────
        print(f"\n  Cumulative scan (pre-fix state: {fix_sha[:8]}^)...")
        r3 = subprocess.run(
            ["git", "rev-parse", f"{fix_sha}^"],
            cwd=tmpdir, capture_output=True, text=True, timeout=10,
        )
        pre_fix = r3.stdout.strip() if r3.returncode == 0 else fix_sha

        subprocess.run(
            ["git", "checkout", "--quiet", pre_fix],
            cwd=tmpdir, capture_output=True, text=True, timeout=30,
        )
        cum_analysis = parse_py_files(tmpdir, fix_files)

        n_flows = len(cum_analysis["taint_flows"])
        n_chains = len(cum_analysis["inter_function_chains"])
        cum_detected = n_flows > 0 or n_chains > 0

        status = "CHAIN DETECTED ⚠" if cum_detected else "no chain ✓"
        print(f"    taint_flows={n_flows}  inter_func_chains={n_chains}  → {status}", flush=True)
        for chain in cum_analysis["inter_function_chains"][:3]:
            print(f"    CHAIN: {chain['evidence']}", flush=True)
        for tf in cum_analysis["taint_flows"][:3]:
            print(f"    TAINT: {tf['function']} → {tf['sink_call']} ({tf['sink_type']})", flush=True)

        result["cumulative_result"] = {
            "sha": pre_fix[:8],
            "taint_flows": cum_analysis["taint_flows"],
            "inter_function_chains": cum_analysis["inter_function_chains"],
            "detected": cum_detected,
        }
        result["postura_detected_cumulative"] = cum_detected

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Summary
    pc_flag = "YES ⚠" if result["postura_detected"] else "NO ✓"
    cum_flag = "YES ⚠" if result["postura_detected_cumulative"] else "NO ✓"
    print(f"\n  Per-commit POSTURA chain detected:   {pc_flag}")
    print(f"  Cumulative POSTURA chain detected:   {cum_flag}")
    if result["first_detection_commit"]:
        print(f"  First detection: commit {result['first_detection_commit']} ({result['detection_type']})")
    else:
        print(f"  POSTURA gap: no chain detected — rule extension needed (see analysis below)")

    return result


def analyse_postura_gaps(results: list[dict], annotations: dict):
    """Explain why POSTURA missed each CVE and what rule would catch it."""
    print(f"\n{'='*60}")
    print("POSTURA GAP ANALYSIS")
    print(f"{'='*60}")

    gap_explanations = {
        "CVE-2026-27602": {
            "gap": "exec_cmd is a custom wrapper — not in POSTURA's sink list (subprocess.*, os.system)",
            "rule_needed": "Add exec_cmd to project-local sink registry, OR extend inter-function taint to trace through wrappers of subprocess/os.system",
            "difficulty": "medium — requires inter-procedural sink propagation (2-hop)",
        },
        "CVE-2026-32247": {
            "gap": "Cypher injection via f-string query construction — no Cypher sink in POSTURA",
            "rule_needed": "Add neo4j driver query methods (session.run, graph.query, etc.) as 'cypher_injection' sinks",
            "difficulty": "low — 3 new sink patterns cover Neo4j + FalkorDB + Graphiti drivers",
        },
        "CVE-2025-10283": {
            "gap": "Path traversal via URL component → Path() → subprocess — Path() not a sink, URL parsing not a source",
            "rule_needed": "Add Path() construction from external-origin strings as path_traversal source; flag when passed to subprocess",
            "difficulty": "high — requires tracking non-HTTP taint sources (URL parsing)",
        },
        "CVE-2026-28490": {
            "gap": "Crypto algorithm registry — architectural issue, not a data flow pattern",
            "rule_needed": "Rule: flag RSA1_5/RC4/MD5 in algorithm registry ALLOWED_ALGORITHMS without explicit deprecation guard",
            "difficulty": "medium — regex rule on algorithm constant definitions + registry population",
        },
        "CVE-2026-33154": {
            "gap": "Jinja2.from_string().render() with external config value — config loading not modelled as taint source",
            "rule_needed": "Add config value loading (os.getenv, dotenv, yaml.load) as taint sources; Jinja2.from_string().render() as code_eval sink",
            "difficulty": "medium — extend source taxonomy beyond HTTP request objects",
        },
    }

    for r in results:
        cve_id = r["cve_id"]
        detected = r["postura_detected"] or r["postura_detected_cumulative"]
        print(f"\n{cve_id}: {'DETECTED ✓' if detected else 'MISSED — gap analysis:'}")
        if not detected and cve_id in gap_explanations:
            g = gap_explanations[cve_id]
            print(f"  Gap:          {g['gap']}")
            print(f"  Rule needed:  {g['rule_needed']}")
            print(f"  Difficulty:   {g['difficulty']}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", nargs="+")
    args = parser.parse_args()

    annotation_paths = []
    if args.cves:
        for cve_id in args.cves:
            p = DATASET / cve_id / "annotation.json"
            if p.exists():
                annotation_paths.append(p)
    else:
        annotation_paths = sorted(DATASET.glob("*/annotation.json"))

    if not annotation_paths:
        print("No annotation.json files found.")
        sys.exit(1)

    print(f"POSTURA sequential-commit evaluation: {[p.parent.name for p in annotation_paths]}")

    all_results = []
    annotations = {}
    for ann_path in annotation_paths:
        result = evaluate_cve_postura(ann_path)
        all_results.append(result)
        annotations[result["cve_id"]] = json.loads(ann_path.read_text())

    # Gap analysis
    analyse_postura_gaps(all_results, annotations)

    # Summary table
    print(f"\n{'='*60}")
    print("POSTURA EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"\n{'CVE':22} {'Per-commit':14} {'Cumulative':14} {'Notes'}")
    print("-" * 72)
    detected_count = 0
    for r in all_results:
        pc = "DETECTED ⚠" if r["postura_detected"] else "missed"
        cu = "DETECTED ⚠" if r["postura_detected_cumulative"] else "missed"
        if r["postura_detected"] or r["postura_detected_cumulative"]:
            detected_count += 1
        note = f"first: commit {r['first_detection_commit']}" if r["first_detection_commit"] else "gap — see analysis"
        print(f"{r['cve_id']:22} {pc:14} {cu:14} {note}")

    print(f"\nPOSTURA detected {detected_count}/{len(all_results)} CVEs "
          f"(with current rules — see gap analysis for extensions)")

    # Save
    output = {"results": all_results, "tool_version": "postura>=0.2.0"}
    (POSTURA_RESULTS / "postura_eval_results.json").write_text(json.dumps(output, indent=2))
    print(f"\nSaved → {POSTURA_RESULTS / 'postura_eval_results.json'}")


if __name__ == "__main__":
    main()
