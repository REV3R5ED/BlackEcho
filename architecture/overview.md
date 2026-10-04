# Architecture — Operation BlackEcho

## Pipeline

```
┌─────────────┐     ┌──────────┐     ┌────────────┐     ┌─────────────┐     ┌─────────┐
│  evidence/  │────▶│ runners/ │────▶│ normalized/│────▶│ correlation/│────▶│ reports/│
│ (synthetic) │     │(8 tools) │     │(common JSON)│    │(timeline)   │     │(analyst) │
└─────────────┘     └──────────┘     └────────────┘     └─────────────┘     └─────────┘
                          │                                    │
                          ▼                                    ▼
                   native outputs                     ┌─────────────┐
                   (raw JSON, kept)                   │   scoring/  │
                                                      │ (vs ground │
                                                      │   truth)   │
                                                      └─────────────┘
```

## Runner contract

Each adapter in `runners/`:

1. Takes evidence paths as input, never reads `ground-truth/`.
2. Invokes the tool CLI at its pinned commit (subprocess, captured).
3. Writes to `runners/output/<tool>/`:
   - `stdout.txt`, `stderr.txt`, `exit_code`, `runtime_ms`
   - `native.json` — the tool's own machine-readable output, verbatim.
4. Exits non-zero only on unexplained failure. A tool reporting
   "not observable" for out-of-scope evidence exits 0 with a structured note.

## Normalization contract

`normalized/<tool>.json` — arrays of envelope records (`schemas/`).
Every record: stable ID, source_tool, source_version, timestamp,
confidence 0–100, provenance (evidence_ref + native_ref), and
`record_kind`: `observed` (the tool saw it) vs `inferred` (derived).

Schema validation fails loudly on missing required fields.

## Correlation

`correlation/timeline.json` — merged, time-ordered events across tools.
`correlation/relationships.json` — typed links (email→attachment,
attachment→endpoint, endpoint→network, network→ioc, ioc→case).

## Scoring

Compares normalized findings against `ground-truth/incident.json`:

- **coverage**: expected indicators/events recovered ÷ expected total
- **false positives**: benign-labeled evidence incorrectly elevated
- **misses**: expected findings not recovered
- **not observable**: tool correctly reports out-of-scope (not a miss)

## Determinism

Evidence generation is seeded. Identical evidence + pinned tool versions
→ byte-stable normalized outputs (timestamps use the scenario clock,
never wall-clock).
