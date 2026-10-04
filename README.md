# Operation BlackEcho

**Stage the breach. Prove the defense.**

BlackEcho is not a ninth security tool. It is the integration and validation
layer for the eight-tool REV3R5ED defensive cybersecurity ecosystem: a
reproducible, end-to-end incident investigation lab.

One synthetic breach — phishing email → user execution → PowerShell →
persistence → network activity — is investigated by every specialist tool,
then reconstructed into a single defensible incident narrative with
ground-truth scoring.

## The eight tools

| Stage | Tool | What it contributes |
|-------|------|---------------------|
| 1 | [PhishScope](https://github.com/REV3R5ED/PhishScope) | Email headers, auth, URLs, attachments, impersonation |
| 2 | [MetaTrace](https://github.com/REV3R5ED/MetaTrace) | Image EXIF/metadata, anomaly review |
| 3 | [HuntForge](https://github.com/REV3R5ED/HuntForge) | Process lineage, PowerShell, persistence, timeline, ATT&CK |
| 4 | [LogLens](https://github.com/REV3R5ED/LogLens) | Log parsing, anomaly scoring, event summaries |
| 5 | [NetScope](https://github.com/REV3R5ED/NetScope) | DNS/TLS/address/path context |
| 6 | [SentinelKit](https://github.com/REV3R5ED/SentinelKit) | IOC extraction, enrichment, STIX export |
| 7 | [AegisForge](https://github.com/REV3R5ED/AegisForge) | Case evidence, PCAP context, correlation, reporting |
| 8 | [AutoOPS](https://github.com/REV3R5ED/AutoOPS) | Environment health, operational validation |

Pinned tool commits: [`manifests/tool-versions.json`](manifests/tool-versions.json)

## The report

Every run produces a Markdown and HTML analyst report. The HTML version:

![BlackEcho investigation report](docs/screenshots/01-report.png)

![BlackEcho timeline](docs/screenshots/02-timeline.png)

## How it works

```
evidence/  →  runners/  →  normalized/  →  correlation/  →  reports/
(synthetic)   (8 tools)    (common JSON)    (timeline+links)   (analyst report)
                  ↑
            ground-truth/ (never read by tools)
                  ↓
               scoring/ (coverage, false positives, misses)
```

1. **Evidence factory** generates deterministic, benign synthetic evidence
   with SHA-256 manifests.
2. **Runners** execute each tool at its pinned commit, capturing stdout,
   stderr, exit codes, and native JSON.
3. **Normalization** converts native output into the common entity contract
   (`schemas/`: Finding, IOC, Artifact, Event, Host, User, Evidence).
4. **Correlation** links email → attachment → endpoint → logs → network →
   IOCs → case into one timeline.
5. **Scoring** compares recovered findings against ground truth: coverage,
   false positives, misses. A tool reporting "not observable" for
   out-of-scope evidence is scored separately from a miss.
6. **Report** reads like an analyst case report, generated from actual run data.

## Safety

All evidence is synthetic or safely generated. No live malware, no real
credentials, no exploit deployment, no harmful infrastructure. See
[SCENARIO.md](SCENARIO.md).

## Reproduce it

```bash
# 1. Install the eight tools at their pinned commits (see manifests/tool-versions.json)
# 2. Generate evidence
python3 evidence_factory.py
# 3. Run the full pipeline
python3 run_blackecho.py
# 4. Read the report
open reports/blackecho-report.md
```

## Repository layout

```
README.md  SCENARIO.md  architecture/
manifests/tool-versions.json   # Phase 0: pinned tool SHAs
evidence/      # Synthetic evidence by type (email, endpoint, logs, ...)
ground-truth/  # Authoritative incident.json — tools never read this
expected-findings/  # Per-tool expected outputs
runners/       # 8 tool adapters (capture native output)
normalized/    # Common-contract JSON entities
correlation/   # Timeline + cross-tool relationships
reports/       # Analyst-style final report
tests/         # schema, adapter, integration, regression, end-to-end
```

## Status

| Phase | Deliverable | State |
|-------|-------------|-------|
| 0 | Portfolio gate (8 repos green, SHAs pinned) | ✅ done |
| 1 | Repo foundation | 🚧 in progress |
| 2 | Evidence factory | ⬜ |
| 3 | Tool adapters | ⬜ |
| 4 | Normalization | ⬜ |
| 5 | Correlation | ⬜ |
| 6 | Scoring | ⬜ |
| 7 | Hardening | ⬜ |
| 8 | Publication | ⬜ |
