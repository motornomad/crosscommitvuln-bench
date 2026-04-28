# Datasheet for CrossCommitVuln-Bench

> Following the Gebru et al. (2021) "Datasheets for Datasets" framework.
> Last updated: 2026-03-29

---

## Motivation

**For what purpose was the dataset created?**

CrossCommitVuln-Bench was created to fill a gap in the vulnerability detection literature: no existing dataset explicitly annotates the *multi-commit introduction pattern*, where an exploitable condition is formed by two or more commits each individually benign to per-commit static analysis (SAST). The dataset provides: (1) ground-truth annotation of contributing commit chains, (2) reproducible SAST baselines establishing how severely snapshot-based tools miss these patterns, and (3) artifacts for evaluating cross-commit detection approaches.

**Who created the dataset and on behalf of what organization?**

Arunabh Majumdar, independent researcher. No organizational affiliation.

**Who funded the creation of the dataset?**

Unfunded. All work was performed independently.

**Any other comments?**

The dataset is a companion artifact to the paper "CrossCommitVuln-Bench: A Dataset of Multi-Commit Python Vulnerabilities Invisible to Per-Commit Static Analysis," submitted to AIware 2026 (co-located with FSE 2026).

---

## Composition

**What do the instances represent?**

Each instance is a real-world Python CVE (Common Vulnerability and Exposure) in which the exploitable condition was introduced across ≥2 distinct commits. Each instance consists of:
- A structured `annotation.json` containing the CVE ID, CWE classification, CVSS severity, contributing commit chain (commit hashes, dates, roles, SAST results per commit), chain description, and why per-commit SAST misses it.
- A `reproduction.md` explaining how to reconstruct the vulnerable state.
- Per-commit and cumulative Semgrep + Bandit SAST results embedded in the annotation.

**How many instances are there?**

- **50 complete+sast** instances (SAST baselines run; 15 with full chain annotation, 35 with skeleton chain descriptions pending human review).
- **5 SKIP** instances (negative examples: selection criteria not met, retained with documented rationale).
- **10 skeleton** instances (archaeology done, awaiting human chain annotation).
- Total: 66 annotated candidates.

*The published AIware 2026 paper reports results on the initial 15 complete+sast CVEs (CCDR=13%, CDR=27%). The remaining 35 are post-publication extensions targeting MSR 2027.*

**Does the dataset contain all possible instances or a sample?**

A curated sample. Starting from 1,200 GitHub Security Advisory (GHSA) Python advisories, we identified 80 candidates with ≥2 Python files changed in the fix commit. Automated git blame on the top 30 confirmed 23 as multi-commit (77%). Manual archaeology on 21 yielded 15 passing all five selection criteria.

**What data does each instance consist of?**

Each `annotation.json` contains:
```
cve_id, repo, cwe_ids, severity_combined, fix_commit,
contributing_commits[]:
  hash, date, role (SOURCE|SINK|GUARD_REMOVAL|EXPANSION|...),
  isolated_severity (low|benign),
  semgrep_findings[], bandit_findings[],
  sast_flagged_relevant (bool),
  isolated_severity_note (optional)
vulnerability_chain:
  description, why_sast_misses_per_commit
commit_span_days,
cumulative_scan: {semgrep_total, bandit_total, any_relevant},
ccdr_this_cve (bool), cdr_this_cve (bool),
annotation_status ("complete+sast" | "SKIP")
```

**Is there a label or target associated with each instance?**

Yes: `ccdr_this_cve` (per-commit SAST detection: True/False) and `cdr_this_cve` (cumulative SAST detection: True/False) are the primary labels. The contributing commit sequence with per-commit `sast_flagged_relevant` values provides fine-grained labels at the commit level.

**Is any information missing from individual instances?**

For 3 CVEs (CVE-2026-28490/Authlib, CVE-2026-32247/Graphiti, CVE-2026-33154/dynaconf), the contributing commits predate 2024 and required full (non-shallow) git clones. For CVEs where contributing commits were beyond the initial shallow clone depth (500), per-commit SAST was conservatively classified as MISSED. Full-clone re-runs are planned for the MSR 2027 extension.

**Are relationships between instances explicit?**

Each instance is independent (different repository, different CVE). No cross-CVE dependency relationships are modeled in this version.

**Are there recommended data splits?**

No official train/test split is defined — this is an evaluation benchmark, not a training dataset. Researchers evaluating cross-commit detection tools should report results on all 15 complete+sast instances.

**Are there any errors, sources of noise, or redundancies?**

- All annotations were produced by a single annotator (see Limitations in the paper).
- Three CVEs were independently re-annotated in a blind condition; all three produced consistent chain descriptions.
- CVE-2025-5120: Bandit B102 fired on a pre-existing `exec()` call in agent runtime code that was not introduced by the chain commits. This false positive was manually overridden; the correction is documented in `isolated_severity_note` for each relevant commit.
- The 6 SKIP instances are intentional negative examples, not errors.

**Is the dataset self-contained?**

The annotations (`annotation.json`, `reproduction.md`) and SAST result data are self-contained in this repository. The underlying source code repositories are publicly accessible on GitHub; they are not mirrored here. Reproduction requires internet access to clone the source repositories.

**Does the dataset contain data that might be considered confidential?**

No. All data is derived from public CVE advisories and open-source repositories.

**Does the dataset contain data that, if viewed directly, might be offensive, insulting, threatening, or might otherwise cause anxiety?**

No. The dataset contains security vulnerability annotations and code snippets. It does not contain personal data, harmful speech, or sensitive imagery.

**Does the dataset relate to people?**

No. The dataset is about software vulnerabilities in open-source Python projects.

**Does the dataset identify any subpopulations?**

No.

---

## Collection Process

**How was the data associated with each instance acquired?**

1. **Mining**: GitHub Security Advisory Database (GHSA) queried via the OSV API. Filtered for high/critical-severity PyPI advisories with traceable fix commits. 1,200 advisories → 80 candidates with ≥2 Python files in the fix diff.
2. **Multi-commit confirmation**: Automated `git blame` on fix-modified lines for top 30 candidates. 23/30 confirmed as multi-commit (77%).
3. **Manual archaeology**: For each candidate, the fix commit diff was read, each vulnerable line was traced to its introducing commit via `git blame`, and the full diff of each introducing commit was read to assess apparent intent and individual benignness.
4. **Annotation**: Structured `annotation.json` written by the annotator; `reproduction.md` written to confirm reproducibility.
5. **SAST baselines**: `scripts/run_baselines.py` ran Semgrep v1.154.0 (`--config auto`) and Bandit v1.9.4 (`-r`) in per-commit mode (checkout each contributing commit) and cumulative mode (checkout `fix_commit^`).

**What mechanisms or procedures were used to collect the data?**

- OSV API (public, no authentication required)
- `git clone`, `git blame`, `git log`, `git diff` (standard git tooling)
- Semgrep v1.154.0 community rules
- Bandit v1.9.4
- Scripts: `scripts/mine_candidates.py`, `scripts/archaeology.py`, `scripts/run_baselines.py`

**If the dataset is a sample of a larger set, what was the sampling strategy?**

Candidates were ranked by the number of distinct blame commits on fix-modified lines (proxy for multi-commit likelihood). The top 30 by this score were archaeologized. Within those 30, all 23 that confirmed as multi-commit were eligible; 21 were fully annotated. 15 passed all five selection criteria.

**Who was involved in the data collection process?**

Single annotator: Arunabh Majumdar. Claude Code (Anthropic) assisted with archaeology automation and SAST run orchestration.

**Over what timeframe was the data collected?**

CVE mining and spike (5 CVEs): 2026-03-21 to 2026-03-26.
Scale-up to 15 CVEs + full SAST baselines: 2026-03-28.

**Were any ethical review processes conducted?**

No formal ethical review. All data is derived from public sources (CVE advisories, public GitHub repositories). No personal data is involved.

**Did you collect the data from the individuals in question directly or indirectly?**

The data is derived from public CVE databases (NVD, GHSA/OSV) and public open-source repositories. No direct collection from individuals.

**Were the individuals in question notified about the data collection?**

Not applicable.

**Did the individuals in question consent to the collection and use of their data?**

Not applicable.

---

## Preprocessing / Cleaning / Labeling

**Was any preprocessing/cleaning/labeling of the data done?**

- **Relevance classification**: SAST findings were manually classified as "relevant" (finding maps to the CVE's CWE and the file/function is in the chain) or "irrelevant" (false positive on unrelated code). Classification rationale is recorded in `sast_flagged_relevant` and accompanying notes.
- **False positive correction**: CVE-2025-5120 — Bandit B102 on pre-existing `exec()` in agent runtime overridden to `sast_flagged_relevant: false`; documented in `isolated_severity_note`.
- **Chain role assignment**: Each contributing commit is assigned a role (`SOURCE`, `SINK`, `GUARD_REMOVAL`, `EXPANSION`, `INFRASTRUCTURE`, `FEATURE`) based on its contribution to the vulnerability chain.

**Was the "raw" data saved in addition to the preprocessed/cleaned/labeled data?**

Yes. Raw `git blame` output and key commit diffs are preserved in `results/archaeology/<CVE_ID>/`. Raw SAST outputs (Semgrep JSON, Bandit JSON) are embedded in `annotation.json` under `semgrep_findings` and `bandit_findings` per commit.

**Is the software that was used to preprocess/clean/label the data available?**

Yes. All scripts are in `scripts/` (MIT License):
- `scripts/mine_candidates.py` — OSV candidate mining
- `scripts/archaeology.py` — git blame + diff extraction
- `scripts/run_baselines.py` — Semgrep + Bandit per-commit + cumulative
- `scripts/compute_metrics.py` — CCDR/CDR/gap metrics from annotations
- `scripts/validate_annotations.py` — jsonschema annotation validator

---

## Uses

**Has the dataset been used for any tasks already?**

Yes. Baseline SAST evaluations using Semgrep and Bandit establish CCDR = 13% (2/15) and CDR = 27% (4/15) as reproducible lower bounds. POSTURA (a graph-based cross-commit detection PoC) achieved 60% detection on the 5-CVE spike subset (3/5 cumulatively).

**What (other) tasks could the dataset be used for?**

1. **Evaluating cross-commit detection tools**: Any tool claiming to detect multi-commit vulnerabilities can be evaluated against the 15 annotated CVEs with ground-truth chain labels.
2. **Training commit-sequence anomaly models**: The contributing commit sequences with `isolated_severity` labels can serve as training examples for models that learn to flag individually benign commits that are part of a dangerous pattern.
3. **CI/CD research**: The dataset motivates systems that maintain persistent security state across commits rather than performing per-PR snapshot scans.
4. **SAST rule improvement**: The `why_sast_misses_per_commit` field in each annotation explicitly documents SAST blind spots, which could guide rule developers.

**Is there anything about the composition of the dataset or the way it was collected and preprocessed/cleaned/labeled that might impact future uses?**

- Python-only: findings may not generalize to other languages.
- Small N (15): statistically, results should be interpreted as directional evidence rather than precise measurements.
- Single annotator: chain annotations reflect one expert's judgment. The `vulnerability_chain.description` and `why_sast_misses_per_commit` fields are interpretive and should be treated as expert annotation, not ground truth.
- SAST tool version sensitivity: Semgrep and Bandit update their rules frequently. Re-running with newer versions may produce different results. Pin to Semgrep v1.154.0 and Bandit v1.9.4 for reproducibility.

**Are there tasks for which the dataset should not be used?**

The dataset should not be used to:
- Train offensive exploit-generation models.
- Identify currently-unpatched vulnerabilities for active exploitation (all CVEs have published fixes).
- Make absolute claims about SAST tool accuracy without appropriate caveats about dataset size and language scope.

---

## Distribution

**Will the dataset be distributed to third parties outside of the entity on behalf of which the dataset was created?**

Yes. The dataset is publicly released.

**How will the dataset be distributed?**

- **GitHub**: `https://github.com/motornomad/crosscommitvuln-bench` (annotations + scripts; MIT for scripts, CC-BY-4.0 for annotations)
- **Zenodo**: Full dataset archive with DOI (pending upload; DOI to be added to paper before submission)

**When will the dataset be distributed?**

Concurrent with paper submission (April 2026).

**Will the dataset be distributed under a copyright or other intellectual property (IP) license?**

- **Annotation files** (`dataset/<CVE_ID>/annotation.json`, `reproduction.md`): CC-BY-4.0
- **Scripts** (`scripts/`): MIT License
- **Underlying source code**: Each CVE's source code retains its original open-source license (Apache 2.0, MIT, BSD, etc.). This dataset does not redistribute source code — only commit hashes and diffs sufficient for reproduction.

**Have any third parties imposed IP-based or other restrictions on the data?**

No. All source repositories are open-source with public commit histories. CVE advisories are public domain (NVD) or CC0 (OSV/GHSA).

**Do any export controls or other regulatory restrictions apply?**

No.

---

## Maintenance

**Who will be supporting/hosting/maintaining the dataset?**

Arunabh Majumdar (GitHub: @motornomad).

**How can the owner/curator/manager of the dataset be reached?**

GitHub issues on `https://github.com/motornomad/crosscommitvuln-bench`.

**Will the dataset be updated?**

Yes. A scale-up to 20 CVEs with CodeQL as a third SAST tool is planned for an MSR 2027 Data Track submission. Updates will be versioned (v1.0 = this AIware submission; v2.0 = MSR 2027 scale-up).

**If the dataset relates to people, are there applicable limits on the retention of the data associated with the instances?**

Not applicable — no personal data.

**Will older versions of the dataset continue to be supported/hosted/maintained?**

Zenodo records are immutable by design. The v1.0 DOI will remain permanently accessible.

**If others want to extend/augment/build on/contribute to the dataset, is there a mechanism for them to do so?**

Contributions welcome via GitHub pull requests. A schema validator (`scripts/validate_annotations.py`) enforces annotation consistency. Proposed additions must satisfy all five selection criteria (multi-commit, individually benign, collectively critical, open source, reproducible) and include SAST baseline results.

**Any other comments?**

The 6 SKIP entries (annotation_status=SKIP) are intentional negative examples demonstrating the selection criteria in action. They are part of the dataset and should be included in any analysis of curation rigor.
