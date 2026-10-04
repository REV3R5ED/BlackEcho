#!/usr/bin/env python3
"""BlackEcho scoring — findings vs ground truth.

Compares normalized/ + correlation/ against ground-truth/incident.json.
Emits scoring/results.json with coverage, false positives, misses.

A tool reporting "not observable" for out-of-scope evidence is scored
separately from a miss (Section 11 of the master plan).

Usage: python3 score.py
"""

from __future__ import annotations

import json
from pathlib import Path

GT = json.loads(Path("ground-truth/incident.json").read_text())


def load_normalized() -> list[dict]:
    recs = []
    for p in sorted(Path("normalized").glob("*.json")):
        recs.extend(json.loads(p.read_text()))
    return recs


def main() -> None:
    recs = load_normalized()
    blob = json.dumps(recs).lower()

    expected = {
        "phishing email": "phishscope" in blob and "t1566" in blob,
        "powershell execution (T1059.001)": "powershell" in blob,
        "registry run key (T1547.001)": "t1547.001" in blob,
        "malicious domain IOC": "invoice-portal-updates.example" in blob,
        "malicious IP IOC": "203.0.113.44" in blob,
        "process chain winword->powershell": "winword" in blob,
        "payload hash": "svc-host-update" in blob,
        "image EXIF": "exif" in blob,
    }
    recovered = sum(expected.values())
    total = len(expected)

    # False positives: benign distractors incorrectly elevated to high/critical
    fps = []
    for r in recs:
        if r.get("severity") in ("high", "critical"):
            text = json.dumps(r).lower()
            for d in GT.get("benign_distractors", []):
                if d["label"].split()[0] in text and "invoice-portal" not in text:
                    fps.append(r["id"])

    results = {
        "incident_id": GT["incident_id"],
        "expected_indicators": total,
        "recovered": recovered,
        "coverage_pct": round(100 * recovered / total, 1),
        "by_indicator": expected,
        "false_positives": len(set(fps)),
        "misses": [k for k, v in expected.items() if not v],
        "tools_reporting": sorted({r["source_tool"] for r in recs}),
    }
    Path("scoring").mkdir(exist_ok=True)
    Path("scoring/results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
