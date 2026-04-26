# CrossCommitVuln-Bench

A curated benchmark of 15 real-world Python CVEs in which the exploitable condition
was introduced across **multiple commits** — each individually benign to per-commit
static analysis — but collectively critical.

**Dataset:** [10.5281/zenodo.19338596](https://doi.org/10.5281/zenodo.19338596) | **Paper:** [arXiv:2604.21917](https://arxiv.org/abs/2604.21917)

> Accepted at **AIWare 2026** — 3rd ACM International Conference on AI-Powered Software, Montreal, July 6–7 2026.

---

## Core finding

CI/CD pipelines run SAST on each commit in isolation. If commit A adds an unsanitized
input source and commit B (weeks or months later) wires it to a dangerous sink, neither
commit triggers a SAST alert alone. The chain only becomes visible with cross-commit state.

**Baseline results (Semgrep 1.154.0 + Bandit 1.9.4):**

| Metric | Result |
|---|---|
| **CCDR** (per-commit detection rate) | **13%** (2/15) |
| **CDR** (cumulative detection rate) | **27%** (4/15) |
| **Detection gap** | 13% |

87% of chains are completely invisible to per-commit SAST. Critically, both per-commit
detections are qualitatively poor: one fires on commits framed as security fixes
(developers suppress the alert), and the other detects only a minor component while
missing the primary vulnerability entirely. Practical CCDR ≈ 0%.

---

## Dataset

15 annotated CVEs + 6 negative examples (excluded with documented rationale):

| CVE | Repo | CWE | Severity | Span |
|---|---|---|---|---|
| CVE-2025-10155 | — | CWE-20/693 | Critical | — |
| CVE-2025-10283 | BBOT | CWE-22 | Critical | 195d |
| CVE-2025-46724 | — | CWE-94 | Critical | — |
| CVE-2025-5120 | — | CWE-94 | Critical | — |
| CVE-2025-55449 | — | CWE-345/798 | Critical | — |
| CVE-2025-61622 | — | CWE-502 | Critical | — |
| CVE-2026-22584 | — | CWE-94 | Critical | — |
| CVE-2026-2472 | — | CWE-79 | High | — |
| CVE-2026-25505 | bambuddy | CWE-306/321 | Critical | — |
| CVE-2026-27602 | Modoboa | CWE-78 | High | 313d |
| CVE-2026-27825 | — | CWE-22/73 | Critical | — |
| CVE-2026-28490 | Authlib | CWE-203/327 | High | 1342d |
| CVE-2026-29065 | — | CWE-22 | High | — |
| CVE-2026-32247 | Graphiti | CWE-943 | High | 25d |
| CVE-2026-33154 | dynaconf | CWE-94/1336 | High | 143d |

Commit spans range from 21 to 1,342 days (mean 245d). All 15 repos are open source
with full commit history. 9 critical severity, 6 high.

Each CVE directory contains:
- `annotation.json` — contributing commits, chain rationale, per-commit SAST results
- `reproduction.md` — step-by-step checkout and verification instructions

---

## Repository structure

```
crosscommitvuln-bench/
├── dataset/
│   └── CVE-YYYY-NNNNN/
│       ├── annotation.json       # ground truth annotation
│       └── reproduction.md       # reproduction instructions
├── scripts/
│   ├── mine_candidates.py        # OSV/GHSA mining + git blame scoring
│   ├── archaeology.py            # git blame + commit archaeology
│   ├── run_baselines.py          # Semgrep + Bandit per-commit + cumulative eval
│   ├── run_postura.py            # POSTURA sequential-commit eval
│   ├── compute_metrics.py        # CCDR, CDR, detection gap
│   └── validate_annotations.py   # jsonschema validator
├── results/
│   ├── summary.json              # final metrics
│   ├── per_cve_results.csv       # per-CVE results table
│   └── candidates_ranked.json    # 80 candidates, 23 confirmed multi-commit
├── paper/
│   └── crosscommitvuln.tex       # companion paper (LaTeX)
└── DATASHEET.md                  # dataset documentation (Gebru et al. template)
```

---

## Reproducing the baselines

You need Python 3.10+, Semgrep, and Bandit installed.

```bash
# Install dependencies
pip install semgrep bandit

# Run baselines on a single CVE (clones to /tmp, auto-deletes after)
python scripts/run_baselines.py --cve CVE-2026-27602

# Run on all CVEs
python scripts/run_baselines.py --all

# Recompute aggregate metrics
python scripts/compute_metrics.py
```

Results are written back into each `dataset/<CVE_ID>/annotation.json`.

---

## Annotation schema

```json
{
  "cve_id": "CVE-YYYY-NNNNN",
  "cwe_ids": ["CWE-XX"],
  "severity_combined": "critical|high",
  "contributing_commits": [
    {
      "hash": "<sha>", "date": "YYYY-MM-DD",
      "role": "SOURCE|SINK|GUARD_REMOVAL|...",
      "isolated_severity": "low|benign",
      "semgrep_findings": [...],
      "bandit_findings": [...],
      "sast_flagged_relevant": false
    }
  ],
  "vulnerability_chain": {
    "description": "...",
    "why_sast_misses_per_commit": "..."
  },
  "commit_span_days": 123,
  "ccdr_this_cve": false,
  "cdr_this_cve": false,
  "annotation_status": "complete+sast"
}
```

---

## Companion tool

[POSTURA](https://github.com/motornomad/postura) is a graph-based cross-commit security
analysis system that maintains a persistent Neo4j threat graph across commits. On the
5-CVE spike subset of this dataset, POSTURA detected 3/5 (60%) using taint analysis and
chain discovery rules — compared to CCDR=0% for per-commit SAST on the same CVEs.

---

## Citation

```bibtex
@dataset{majumdar2026crosscommitvulnbench,
  author    = {Majumdar, Arunabh},
  title     = {CrossCommitVuln-Bench: A Dataset of Multi-Commit Python Vulnerabilities
               Invisible to Per-Commit Static Analysis},
  year      = {2026},
  version   = {1.0.0},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.19338596},
  url       = {https://doi.org/10.5281/zenodo.19338596}
}
```

---

## License

Dataset annotations: [CC-BY-4.0](LICENSE_annotations).
Scripts: [MIT](LICENSE_scripts).
External repositories retain their own licenses.
