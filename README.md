# CrossCommitVuln-Bench

A benchmark dataset and evaluation framework for cross-commit vulnerability detection.

**Core finding:** Vulnerabilities can emerge from the *combination* of 2+ commits where each individual commit appears benign or low-severity to standard SAST tools (Semgrep, CodeQL, Bandit).

**Target venue:** MSR 2027 Data Track (4 pages). Submission window: ~Oct-Nov 2026.

## The hypothesis

CI/CD pipelines run SAST on each PR in isolation. If commit A adds an unsanitized input source and commit B (weeks later, different author) wires it to a SQL sink, neither commit triggers a SAST alert alone. The chain only becomes visible with temporal, cross-commit state — exactly what POSTURA's Neo4j threat graph provides.

## Repository structure

```
CrossCommitVuln-Bench/
├── dataset/
│   └── CVE-YYYY-NNNNN/
│       ├── annotation.json       # schema: see docs/CROSSCOMMITVULN-BENCH-PLAN.md §1.4
│       └── reproduction.md       # step-by-step checkout + verification
├── scripts/
│   ├── mine_candidates.py        # Phase 1 (API) + Phase 2 (git blame)
│   ├── run_baselines.py          # Semgrep + Bandit + CodeQL per-commit eval (Sprint 2)
│   ├── run_postura.py            # POSTURA sequential-commit eval (Sprint 3)
│   └── compute_metrics.py        # CCDR, CDR, detection gap (Sprint 2)
├── results/
│   ├── candidates_raw.json       # Phase 1 output
│   ├── candidates_ranked.json    # Phase 2 output (git blame scored)
│   └── spike_findings.md         # Go/no-go decision doc (end of spike week)
└── paper/
    └── crosscommitvuln.tex       # LaTeX (Sprint 4)
```

## Quick start (spike)

```bash
cd /home/arunabh_majumdar/crosscommitvuln-bench

# Recommended: set GitHub token for 5000 req/hr (vs 60 without)
export GITHUB_TOKEN=<your_classic_pat>

# Phase 1 only: API mining (~10 min, ~50 API calls)
/home/arunabh_majumdar/postura/.venv/bin/python scripts/mine_candidates.py --phase 1

# Phase 2 only: git blame on Phase 1 results (~30-60 min)
/home/arunabh_majumdar/postura/.venv/bin/python scripts/mine_candidates.py --phase 2 --top 30

# Both phases end-to-end
/home/arunabh_majumdar/postura/.venv/bin/python scripts/mine_candidates.py --phase all --top 30
```

## Key metrics

| Metric | Definition |
|---|---|
| **CCDR** | Cross-Commit Detection Rate — % of CVEs where per-commit SAST flagged anything relevant |
| **CDR** | Cumulative Detection Rate — % caught when all contributing commits are present |
| **Detection gap** | CDR − CCDR — the gap POSTURA fills |

## Spike success criteria

All three required to proceed to full sprint:
1. 3+ CVEs fully annotated with confirmed multi-commit introduction chains
2. Per-commit Semgrep + Bandit misses the vulnerability on each individual commit
3. POSTURA fires correctly on ≥2 of the 3 when fed commits sequentially

## Full plan

See `/home/arunabh_majumdar/postura/docs/CROSSCOMMITVULN-BENCH-PLAN.md`

## License

Dataset annotations: CC-BY-4.0. Scripts: MIT. External repos retain their own licenses.
